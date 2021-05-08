import sys

# CGI
import cgi
import cgitb
cgitb.enable()
import html as HTML

# セッション管理関係
import bcrypt
import jwt as JWT
from http import cookies
import datetime

# sqlite3
import sqlite3

# データベースファイルのパス
dbname = "./db/database.db"

# テーブルの作成
con = sqlite3.connect(dbname)
cur = con.cursor()
create_table = "create table if not exists users (userid integer primary key, username varchar(64) unique, password varchar(128))"
cur.execute(create_table)
create_table = "create table if not exists comments (commentid integer primary key, username varchar(64), content varchar(140), likes integer,created_at timestamp default (DATETIME('now','localtime')))"
cur.execute(create_table)
con.commit()
cur.close()
con.close()

def readCookie(cookie):
    dic = {}
    tmp1 = cookie.split("; ")
    for tmp2 in tmp1:
        pair = tmp2.split("=")
        dic[pair[0]]=pair[1]
    return dic

def isValidPassword(username,password):
    hashedPassword=""
    # データベース接続とカーソル生成
    con = sqlite3.connect(dbname)
    cur = con.cursor()
    con.text_factory = str

    # SQL実行
    sql = "select * from users where username = ?"
    for row in cur.execute(sql,(username,)):
        hashedPassword = row[2] #usernameが一致したユーザのパスワード(UNIQUE制約により一意)
    cur.close()
    con.close()
    return bcrypt.checkpw(password,hashedPassword)

def issueJwt(username):
    hashedPassword=""
    # データベース接続とカーソル生成
    con = sqlite3.connect(dbname)
    cur = con.cursor()
    con.text_factory = str

    # SQL実行
    sql = "select * from users where username = ?"
    for row in cur.execute(sql,(username,)):
        hashedPassword = row[2] #usernameが一致したユーザのパスワード(UNIQUE制約により一意)
    cur.close()
    con.close()
    return JWT.encode({"name":"{}".format(username)},hashedPassword,algorithm="HS256")

def decodeJwt(token):
    hashedPassword=""

    username = JWT.decode(token,options={"verify_signature": False},algorithms=["HS256"]).get("name")

    # データベース接続とカーソル生成
    con = sqlite3.connect(dbname)
    cur = con.cursor()
    con.text_factory = str

    # SQL実行
    sql = "select * from users where username = ?"
    for row in cur.execute(sql,(username,)):
        hashedPassword = row[2] #usernameが一致したユーザのパスワード(UNIQUE制約により一意)

    cur.close()
    con.close()
    return JWT.decode(token,hashedPassword,algorithms=["HS256"])["name"]

def application(env,start_response):

    # HTMLの先頭と末尾は外部ファイルから読み込み
    f = open("./static/head","r",encoding="utf-8")
    html_head = f.read()
    f = open("./static/tail","r",encoding="utf-8")
    html_tail = f.read()
    html_body = ""
    cookie = cookies.SimpleCookie()
    setCookieFlag = False
    # パスを取得
    path = env["PATH_INFO"]

    # フォームデータを取得
    form = cgi.FieldStorage(environ=env,keep_blank_values=True,fp=env["wsgi.input"])

    if path == "/" or ("HTTP_COOKIE" not in env and (path != "/login" and path != "/registration" and path != "/register")) or ("HTTP_COOKIE" in env and "jwt" not in readCookie(env.get("HTTP_COOKIE"))): #トップページ
        if ("HTTP_COOKIE" not in env) or ("jwt" not in readCookie(env.get("HTTP_COOKIE"))): #jwtクッキーなしの場合
            html_body += \
                    "<div class=\"top\">"\
                    "<h1>ログインフォーム</h1>"\
                    "利用するにはログインしてください。<br>\n"\
                    "<form method=\"POST\" action=\"/login\">\n" \
                    "ユーザー名<input type=\"text\" name=\"username\"><br>\n" \
                    "パスワード<input type=\"password\" name=\"password\"><br>\n" \
                    "<input type=\"submit\" value=\"ログイン\">\n" \
                    "</form><br>\n" \
                    "<span style=\"color:lightgray;font-size:small\">初めての方は<a style=\"color:lightgray\" href=\"/registration\">新規登録</a>をお願いします。</span><br>\n"\
                    "</div>"
        else:
            html_body += \
                    "<META http-equiv=\"Refresh\" content=\"0;URL=/home\">"
            # ログイン済みならホーム画面へ飛ばす
    elif path=="/home":
        username = ""
        try:
            username = decodeJwt(readCookie(env.get("HTTP_COOKIE")).get("jwt"))
        except JWT.InvalidSignatureError:
            setCookieFlag=True
            expiration = datetime.datetime.utcnow() - datetime.timedelta(days=1)
            cookie["jwt"] = ""
            cookie["jwt"]["expires"] = expiration.strftime("%a, %d-%b-%Y %H:%M:%S GMT")
            html_body += \
                    "トークンが無効です、ログインをやりなおしてください。"\
                    "<META http-equiv=\"Refresh\" content=\"2;URL=/\">"
        else:
            con = sqlite3.connect(dbname)
            cur = con.cursor()
            con.text_factory = str
            sql = "select * from comments"
            html_body += \
                    "<h1>ホーム画面</h1>"\
                    "<div>"\
                    "<a href=\"/compose\">発言する</a><br>"\
                    "<a href=\"/search\">検索する</a>"\
                    "</div>"
            html_body += \
                    "<div class=\"comments\">\n" \
                    "<ul>\n"
            for row in cur.execute(sql):
                html_body += "<li>"\
                        "{}:{} <a href=\"/like?id={}\" style=\"color:red;\">&#9829;{}</a> ({})".format(row[1],row[2],row[0],row[3],row[4])
                if username == row[1]:
                    html_body += \
                            " <a href=\"/delete?id={}\">削除</a>".format(row[0])
            cur.close()
            con.close()
            html_body +="</li>\n"\
                    "</ul>\n" \
                    "</div>\n"

    elif path == "/compose": #発言内容の入力
            html_body += \
                    "<h1>投稿フォーム</h1>"\
                    "<div class=\"login\">\n" \
                    "<form method=\"POST\" action=\"/post\">\n" \
                    "<textarea rows=\"4\" cols=\"40\" name=\"content\" placeholder=\"発言を入力してください\"></textarea><br>\n" \
                    "<input type=\"submit\" value=\"投稿\">\n" \
                    "</form>\n" \
                    "</div>\n"

    elif path == "/list": #検索内容の表示
        username = ""
        try:
            username = decodeJwt(readCookie(env.get("HTTP_COOKIE")).get("jwt"))
        except JWT.InvalidSignatureError:
            setCookieFlag=True
            expiration = datetime.datetime.utcnow() - datetime.timedelta(days=1)
            cookie["jwt"] = ""
            cookie["jwt"]["expires"] = expiration.strftime("%a, %d-%b-%Y %H:%M:%S GMT")
            html_body += \
                    "トークンが無効です、ログインをやりなおしてください。"\
                    "<META http-equiv=\"Refresh\" content=\"2;URL=/\">"
        else:
            content = form.getfirst("content")
            content = HTML.escape(content)
            con = sqlite3.connect(dbname)
            cur = con.cursor()
            con.text_factory = str
            sql = "select * from comments where content like ?"
            html_body += \
                    "<h1>検索結果</h1>"\
                    "<div class=\"comments\">\n" \
                    "<ul>\n"
            for row in cur.execute(sql,("%"+content+"%",)):
                html_body += "<li>"\
                        "{}:{} <a href=\"/like?id={}\" style=\"color:red;\">&#9829;{}</a> ({})<br>".format(row[1],row[2],row[0],row[3],row[4])
                if username == row[1]:
                    html_body += \
                            " <a href=\"/delete?id={}\">削除</a>".format(row[0])
            cur.close()
            con.close()
            html_body +="</li>\n"\
                    "</ul>\n" \
                    "</div>\n"\
                    "<a href=\"/home\">ホームに戻る</a>\n"

    elif path == "/like": #いいねの実行
        commentid = form.getfirst("id")
        if commentid == None:
            html_body = \
                    "<META http-equiv=\"Refresh\" content=\"0;URL=/\">" #URL直打ち等でIDを指定しなかった場合
        else:
            # 本来ならAjaxをつかってPUTでやりたいが……
            con = sqlite3.connect(dbname)
            cur = con.cursor()
            con.text_factory = str
            sql = "update comments set likes=likes+1 where commentid = ?"
            cur.execute(sql,(commentid,))
            con.commit()
            cur.close()
            con.close()
            html_body += \
                    "<META http-equiv=\"Refresh\" content=\"0;URL=/home\">"

    elif path == "/post" and env.get("REQUEST_METHOD")=="POST": #投稿を実行
        username = ""
        # フォームから発言内容を取得
        content = form.getfirst("content")
        content = HTML.escape(content)

        try:
            username = decodeJwt(readCookie(env.get("HTTP_COOKIE")).get("jwt"))
        except JWT.InvalidSignatureError:
            setCookieFlag=True
            expiration = datetime.datetime.utcnow() - datetime.timedelta(days=1)
            cookie["jwt"] = ""
            cookie["jwt"]["expires"] = expiration.strftime("%a, %d-%b-%Y %H:%M:%S GMT")
            html_body += \
                    "トークンが無効です、ログインをやりなおしてください。"\
                    "<META http-equiv=\"Refresh\" content=\"2;URL=/\">"
        else:
            con = sqlite3.connect(dbname)
            cur = con.cursor()
            con.text_factory = str

            sql = "insert into comments (username, content, likes) values (?,?,?)"
            cur.execute(sql, (username,content,0))
            con.commit()
            html_body += \
                    "<META http-equiv=\"Refresh\" content=\"0;URL=/home\">"
            cur.close()
            con.close()

    elif path == "/delete": #投稿削除を実行
        commentid = form.getfirst("id")
        if commentid == None:
            html_body = \
                    "<META http-equiv=\"Refresh\" content=\"0;URL=/\">" #URL直打ち等でIDを指定しなかった場合
        else:
            username = ""
            try:
                username = decodeJwt(readCookie(env.get("HTTP_COOKIE")).get("jwt"))
            except JWT.InvalidSignatureError:
                setCookieFlag=True
                expiration = datetime.datetime.utcnow() - datetime.timedelta(days=1)
                cookie["jwt"] = ""
                cookie["jwt"]["expires"] = expiration.strftime("%a, %d-%b-%Y %H:%M:%S GMT")
                html_body += \
                        "トークンが無効です、ログインをやりなおしてください。"\
                        "<META http-equiv=\"Refresh\" content=\"2;URL=/\">"
            else:
                con = sqlite3.connect(dbname)
                cur = con.cursor()
                con.text_factory = str

                sql = "select username from comments where commentid = ?"
                name = cur.execute(sql, (commentid,)).fetchone()
                if name == None:
                    html_body = \
                            "発言が存在しません。"\
                            "<META http-equiv=\"Refresh\" content=\"2;URL=/home\">"
                elif name[0] != username:
                    html_body = \
                            "削除権限がありません。"\
                            "<META http-equiv=\"Refresh\" content=\"2;URL=/home\">"
                else:
                    sql = "delete from comments where commentid = ?"
                    cur.execute(sql, (commentid,))
                    con.commit()
                    html_body += \
                            "<META http-equiv=\"Refresh\" content=\"0;URL=/home\">"
                cur.close()
                con.close()

    elif path == "/search": #検索内容の入力
            html_body += \
                    "<h1>検索フォーム</h1>"\
                    "<div class=\"search\">\n" \
                    "<form method=\"POST\" action=\"/list\">\n" \
                    "<input type=\"text\" name=\"content\">を含む発言<br>\n" \
                    "<input type=\"submit\" value=\"検索\">\n" \
                    "</form>\n" \
                    "</div>\n"

    elif path == "/registration": #登録受付部分
        html_body += \
            "<h1>新規登録フォーム</h1>"\
            "<div class=\"register\">\n" \
            "<form method=\"POST\" action=\"/register\">\n" \
            "ユーザー名<input type=\"text\" name=\"username\"><br>\n" \
            "パスワード<input type=\"password\" name=\"password\"><br>\n" \
            "<input type=\"submit\" value=\"登録\">\n" \
            "</form>\n" \
            "</div>\n"

    elif path == "/register" and env["REQUEST_METHOD"] == "POST": #登録実行部分
        # フォームから各フィールド値を取得
        username = form.getfirst("username")
        username = HTML.escape(username)
        password = form.getfirst("password").encode("utf-8")

        # ソルト/パスワードハッシュ生成
        salt = bcrypt.gensalt()
        hashedPassword = bcrypt.hashpw(password,salt)

        con = sqlite3.connect(dbname)
        cur = con.cursor()
        con.text_factory = str

        sql = "insert into users (username, password) values (?,?)"
        cur.execute(sql, (username,hashedPassword))
        con.commit()
        jwt = issueJwt(username)

        cur.close()
        con.close()

        expiration = datetime.datetime.utcnow() + datetime.timedelta(days=1)
        cookie["jwt"] = jwt
        cookie["jwt"]["domain"] = "localhost"
        cookie["jwt"]["path"] = "/"
        cookie["jwt"]["expires"] = expiration.strftime("%a, %d-%b-%Y %H:%M:%S GMT")
        setCookieFlag=True

        html_body += \
                "登録されました、ホーム画面へ移動します。<br>\n"\
                "<META http-equiv=\"Refresh\" content=\"2;URL=/home\">"

    elif path == "/login":
        # フォームから各フィールド値を取得
        username = form.getfirst("username")
        username = HTML.escape(username)
        password = form.getfirst("password").encode(encoding="utf-8")

        if isValidPassword(username,password):

            jwt = issueJwt(username) #jwt発行

            exp = datetime.datetime.now() + datetime.timedelta(days=1)
            cookie["jwt"] = jwt
            cookie["jwt"]["domain"] = "localhost" #localhost
            cookie["jwt"]["path"] = "/" #全域
            cookie["jwt"]["expires"] = exp.strftime("%a %d %b %Y %H:%M:%S GMT") #有効期限1日
            setCookieFlag=True

            html_body += \
                    "認証されました、ホーム画面へ移動します。<br>\n"\
                    "<META http-equiv=\"Refresh\" content=\"2;URL=/home\">"

    # elif path == "/list":
    else:
        html_body = \
                "<META http-equiv=\"Refresh\" content=\"0;URL=/\">"


    html = html_head + html_body + html_tail
    html = html.encode("utf-8")

    # レスポンス
    if setCookieFlag:
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8"),
            ("Set-Cookie",cookie["jwt"].OutputString()),
            ("Content-Length", str(len(html))) ])
        setCookieFlag=False
    else:
        start_response("200 OK", [("Content-Type", "text/html; charset=utf-8"),
            ("Content-Length", str(len(html))) ])
    return [html]

# リファレンスWEBサーバを起動
#  ファイルを直接実行する（python3 test_wsgi.py）と，
#  リファレンスWEBサーバが起動し，http://localhost:8080 にアクセスすると
#  このサンプルの動作が確認できる．
#  コマンドライン引数にポート番号を指定（python3 test_wsgi.py ポート番号）した場合は，
#  http://localhost:ポート番号 にアクセスする．
from wsgiref import simple_server
if __name__ == "__main__":
    port = 8080
    if len(sys.argv) == 2:
       port = int(sys.argv[1])

    server = simple_server.make_server("", port, application)
    server.serve_forever()
