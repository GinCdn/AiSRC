package core

import (
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
	"time"

	"AiSRC/config"
	"AiSRC/global"
	"AiSRC/utils"

	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"gorm.io/gorm/schema"
)

// Db 全局数据库实例。
var Db *gorm.DB

// MysqlInit 初始化 MySQL 连接。参考 GinBlog：显式指定东八区、开启预编译、配置连接池。
func MysqlInit() error {
	dbConfig := config.AppConfig.Mysql

	location := url.QueryEscape("Asia/Shanghai")
	mysqlTimeZone := url.QueryEscape("'+08:00'")
	dsn := fmt.Sprintf(
		// 连接排序规则与建表参数保持一致，避免跨表比较时出现 collation 混用错误。
		"%s:%s@tcp(%s:%d)/%s?charset=%s&collation=utf8mb4_general_ci&parseTime=True&loc=%s&time_zone=%s",
		dbConfig.Username,
		dbConfig.Password,
		dbConfig.Host,
		dbConfig.Port,
		dbConfig.Database,
		dbConfig.Charset,
		location,
		mysqlTimeZone,
	)

	logMode := logger.Warn
	if config.AppConfig.System.Env == "debug" {
		logMode = logger.Info
	}

	// 调度器会高频轮询「还有没有 queued 目标」，查无记录是正常语义，
	// 用默认 logger 会每 5 秒刷两行 "record not found" 把控制台冲掉。
	gormLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags),
		logger.Config{
			SlowThreshold:             200 * time.Millisecond,
			LogLevel:                  logMode,
			IgnoreRecordNotFoundError: true,
			Colorful:                  false,
		},
	)

	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{
		Logger:                                   gormLogger,
		DisableForeignKeyConstraintWhenMigrating: true,
		PrepareStmt:                              true,
		SkipDefaultTransaction:                   true,
		NowFunc:                                  func() time.Time { return utils.Now() },
		NamingStrategy: schema.NamingStrategy{
			TablePrefix:   "",
			SingularTable: false,
		},
	})
	if err != nil {
		return fmt.Errorf("[MySQL]连接失败：%w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("[MySQL]连接池获取失败：%w", err)
	}
	sqlDB.SetMaxIdleConns(dbConfig.MaxIdle)
	sqlDB.SetMaxOpenConns(dbConfig.MaxOpen)

	// 连接寿命必须短于服务端的 wait_timeout，否则连接池会一直复用已被服务端
	// 单方面关闭的空闲连接，表现为「闲置一段时间后的第一个请求探针失败 / 报
	// invalid connection」。集成环境里这个值往往很小（小皮 MySQL 5.7 默认只有
	// 120 秒），所以这里动态读取服务端配置再取其一半，并做上下限保护。
	idle := serverIdleTimeout(db)
	sqlDB.SetConnMaxIdleTime(idle)
	sqlDB.SetConnMaxLifetime(idle * 4)

	if err := sqlDB.Ping(); err != nil {
		return fmt.Errorf("[MySQL]连接失败：%w", err)
	}

	global.Log.Infof("[MySQL]连接池就绪：maxIdle=%d maxOpen=%d connMaxIdleTime=%s（服务端 wait_timeout=%s）",
		dbConfig.MaxIdle, dbConfig.MaxOpen, idle, idle*2)

	Db = db
	global.Log.Info("[MySQL]连接成功")
	return nil
}

// serverIdleTimeout 读取服务端 wait_timeout 并换算为安全的连接空闲回收时间。
//
// 取服务端值的一半，并夹在 [10s, 60s] 区间内：过小会导致频繁重连，过大则可能
// 超出 wait_timeout 而拿到死连接。读取失败时退回 30 秒的保守值。
func serverIdleTimeout(db *gorm.DB) time.Duration {
	const (
		minIdle = 10 * time.Second
		maxIdle = 60 * time.Second
		fallbac = 30 * time.Second
	)

	var waitTimeout int
	if err := db.Raw("SELECT @@wait_timeout").Scan(&waitTimeout).Error; err != nil || waitTimeout <= 0 {
		return fallbac
	}

	idle := time.Duration(waitTimeout) * time.Second / 2
	if idle < minIdle {
		return minIdle
	}
	if idle > maxIdle {
		return maxIdle
	}
	return idle
}

// TableOptions 建表参数。
//
// 必须显式指定，不能依赖服务端默认值：
//  1. ENGINE=InnoDB —— 部分集成环境（如 phpstudy 的 my.ini）会把
//     default-storage-engine 设为 MyISAM。MyISAM 没有事务与行锁，
//     多 Agent 并发调度跑在上面会出现脏读与丢更新；同时它的索引上限只有
//     1000 字节，会让 (task_id, host, source) 这类复合唯一索引直接建表失败。
//  2. ROW_FORMAT=DYNAMIC —— 配合 innodb_large_prefix 把索引长度上限提到
//     3072 字节，避免长文本复合索引报 Error 1071。
//  3. DEFAULT CHARSET=utf8mb4 —— 服务端常见默认值是 utf8（utf8mb3，3 字节），
//     无法保存 4 字节字符；大模型输出经常带 emoji，必须显式用 utf8mb4。
const TableOptions = "ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci ROW_FORMAT=DYNAMIC"

// AutoMigrate 迁移全部业务表。
func AutoMigrate(models ...interface{}) error {
	if Db == nil {
		return fmt.Errorf("[MySQL]数据库未初始化")
	}

	if err := Db.Set("gorm:table_options", TableOptions).AutoMigrate(models...); err != nil {
		return fmt.Errorf("%w（提示：若为 Error 1071，请确认 MySQL 为 InnoDB 且 innodb_large_prefix=ON）", err)
	}

	// 兜底修复：历史遗留或被环境默认值建成的非 InnoDB 表统一转回 InnoDB。
	// 这一步很关键——MyISAM 表上的写入不参与事务，会让调度状态机出现难以排查的数据不一致。
	return normalizeTableEngine(models)
}

// normalizeTableEngine 把非 InnoDB 的业务表转换为 InnoDB。
func normalizeTableEngine(models []interface{}) error {
	stmt := &gorm.Statement{DB: Db}
	for _, item := range models {
		if err := stmt.Parse(item); err != nil {
			return err
		}
		table := stmt.Schema.Table

		var engine string
		row := Db.Raw(
			"SELECT engine FROM information_schema.tables WHERE table_schema = DATABASE() AND table_name = ?",
			table,
		).Row()
		if err := row.Scan(&engine); err != nil {
			// 表不存在或查询失败时跳过，不阻断启动。
			continue
		}
		if strings.EqualFold(engine, "InnoDB") {
			continue
		}

		global.Log.Warnf("[MySQL]表 %s 当前引擎为 %s，正在转换为 InnoDB", table, engine)
		if err := Db.Exec(fmt.Sprintf("ALTER TABLE `%s` ENGINE=InnoDB ROW_FORMAT=DYNAMIC", table)).Error; err != nil {
			return fmt.Errorf("[MySQL]表 %s 转换 InnoDB 失败：%w", table, err)
		}
	}
	return nil
}
