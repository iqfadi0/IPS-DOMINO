from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)

# كلمة المرور الثابتة - غيرها حسب حاجتك
CORRECT_PASSWORD = "Fadi!!@@"

@app.route("/")
def index():
    error = request.args.get('error')  # نمرر رسالة الخطأ عبر الرابط لو موجودة
    return render_template("index.html", error=error)

@app.route("/login", methods=["POST"])
def login():
    password = request.form.get("password")
    if password == CORRECT_PASSWORD:
        return redirect("/dashboard")
    else:
        return redirect(url_for("index", error="Invalid password. Please try again."))

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

@app.route("/change-password", methods=["GET", "POST"])
def change_password():
    if request.method == "POST":
        # منطق تغيير كلمة المرور (مؤقت - تحتاج تضيف تخزين حقيقي)
        return redirect("/dashboard")
    return render_template("change_password.html")

if __name__ == '__main__':
    from os import environ
    app.run(host='0.0.0.0', port=int(environ.get('PORT', 5000)))
