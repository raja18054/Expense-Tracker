
from flask import Flask, render_template, request, redirect
import csv
import pandas as pd
import os

app = Flask(__name__)

FILE = "expenses.csv"

# create file if not exists
if not os.path.exists(FILE):
    with open(FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Date", "Category", "Amount", "Note"])

@app.route("/")
def index():
    data = []
    with open(FILE, "r") as f:
        reader = csv.reader(f)
        next(reader)
        for row in reader:
            data.append(row)
    return render_template("index.html", data=data)

@app.route("/add", methods=["GET","POST"])
def add():
    if request.method == "POST":
        date = request.form["date"]
        category = request.form["category"]
        amount = request.form["amount"]
        note = request.form["note"]

        with open(FILE, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([date, category, amount, note])

        return redirect("/")

    return render_template("add.html")

@app.route("/report")
def report():
    df = pd.read_csv(FILE)
    total = df["Amount"].astype(float).sum()
    category = df.groupby("Category")["Amount"].sum()
    return render_template("report.html", total=total, category=category)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
