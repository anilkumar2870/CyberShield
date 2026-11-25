from flask import Flask, render_template, request
from modules.network_discovery import discover_network

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def dashboard():

    result = None
    target = ""

    if request.method == "POST":

        target = request.form.get("network", "").strip()

        result = discover_network(target)

    return render_template(
        "index.html",
        result=result,
        target=target
    )


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
