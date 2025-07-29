from flask import Flask, render_template, request, redirect

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/login", methods=["POST"])
def login():
    return redirect("/dashboard")

@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")

@app.route("/change-password", methods=["GET", "POST"])
def change_password():
    if request.method == "POST":
        # Change password logic here
        return redirect("/dashboard")
    return render_template("change_password.html")

if __name__ == "__main__":
    app.run(debug=True)