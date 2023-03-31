package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"

	_ "github.com/glebarez/go-sqlite"
	"golang.org/x/crypto/bcrypt"
)

// “db”将保存对我们数据库实例的引用
var db *sql.DB

func main() {
	// "Signin" 和 "Signup" 是我们要实现的处理函数
	http.HandleFunc("/signin", Signin)
	http.HandleFunc("/signup", Signup)
	// 初始化我们的数据库连接
	initDB()
	// 在端口 8000 上启动服务器
	log.Fatal(http.ListenAndServe(":8000", nil))
}

func initDB() {
	var err error
	// 连接到 sqlite 数据库
	db, err = sql.Open("sqlite", "./mydb")
	if err != nil {
		panic(err)
	}
}

// 创建一个对用户模型
type Credentials struct {
	Password string `json:"password", db:"password"`
	Username string `json:"username", db:"username"`
}

func Signup(w http.ResponseWriter, r *http.Request) {
	// 将请求主体解析并解码为 `Credentials` 实例
	creds := &Credentials{}
	err := json.NewDecoder(r.Body).Decode(creds)
	if err != nil {
		// 如果请求体有问题，返回 400 状态
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// 使用 bcrypt 算法对密码进行加盐和哈希散列处理
	// 第二个参数是散列的成本，我们设置为 8（这个值可以任意设置，可以多也可以少，取决于你希望利用的计算能力）
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(creds.Password), 8)

	// 接下来，将用户名和哈希处理后的密码插入数据库
	if _, err = db.Exec("insert into users values (?, ?)", creds.Username, string(hashedPassword)); err != nil {
		// 如果插入数据库有任何问题，返回 500 错误
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// 到此，我们完成了数据库的保存，将默认返回状态 200
}

func Signin(w http.ResponseWriter, r *http.Request) {
	// 将请求体解析为 `Credentials` 实例
	creds := &Credentials{}
	err := json.NewDecoder(r.Body).Decode(creds)
	if err != nil {
		// 如果请求体有问题，返回 400 状态
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// 根据请求用户名获取数据库中对应的用户
	result := db.QueryRow("select password from users where username=?", creds.Username)
	if err != nil {
		// 如果数据库有问题，返回 500 错误
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	// 我们创建另一个 `Credentials` 实例来存储我们从数据库中获取的凭据
	storedCreds := &Credentials{}
	// 将获得的密码存储在 storedCreds 中
	err = result.Scan(&storedCreds.Password)
	if err != nil {
		// 如果登录用户名不存在，则发送“未授权”(401) 状态
		if err == sql.ErrNoRows {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// 如果错误是任何其他类型，则发送 500 状态
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// 将数据库中的哈希密码与用户当前登录的密码的哈希版本进行比较
	if err = bcrypt.CompareHashAndPassword([]byte(storedCreds.Password), []byte(creds.Password)); err != nil {
		// 如果两个密码不匹配，返回 401 状态
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// 到达这里，就意味着用户密码是正确的，并且他们被授权
	// 默认将返回200状态
}
