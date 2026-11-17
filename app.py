import os
import re
import secrets
import psycopg2

from flask import (
    Flask, render_template, render_template_string, request,
    redirect, url_for, session, flash
)
from werkzeug.security import (
    generate_password_hash, check_password_hash
)
from functools import wraps

app = Flask(__name__)

app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    "change-this-secret-before-production"
)

DATABASE_URL = os.environ.get("DATABASE_URL")

def get_db():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not configured")
    return psycopg2.connect(DATABASE_URL)


def init_db():
    con = get_db()
    cur = con.cursor()

    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            fullname VARCHAR(120) NOT NULL,
            email VARCHAR(150) UNIQUE NOT NULL,
            username VARCHAR(50) UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            balance NUMERIC(12,2) DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cur.execute("""
        CREATE INDEX IF NOT EXISTS users_email_idx
        ON users(email)
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS farm_activations (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            plan_name TEXT NOT NULL,
            capital NUMERIC(12,2) NOT NULL,
            daily_reward NUMERIC(12,2) NOT NULL,
            days_paid INTEGER NOT NULL DEFAULT 0,
            activated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            next_reward_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT NOT NULL DEFAULT 'active'
        )
    """)

    cur.execute("""
        CREATE TABLE IF NOT EXISTS farm_transactions (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            transaction_type TEXT NOT NULL,
            amount NUMERIC(12,2) NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cur.execute("""
        CREATE INDEX IF NOT EXISTS farm_activations_user_idx
        ON farm_activations(user_id)
    """)

    cur.execute("""
        CREATE INDEX IF NOT EXISTS farm_transactions_user_idx
        ON farm_transactions(user_id)
    """)

    cur.execute("""
        ALTER TABLE users
        ADD COLUMN IF NOT EXISTS is_admin BOOLEAN NOT NULL DEFAULT FALSE
    """)

    cur.execute("""
        ALTER TABLE users
        ADD COLUMN IF NOT EXISTS referral_reward_paid BOOLEAN NOT NULL DEFAULT FALSE
    """)

    cur.execute("""
        ALTER TABLE users
        ADD COLUMN IF NOT EXISTS name VARCHAR(120)
    """)

    cur.execute("""
        ALTER TABLE users
        ADD COLUMN IF NOT EXISTS password TEXT
    """)

    cur.execute("""
        ALTER TABLE users
        ADD COLUMN IF NOT EXISTS full_name VARCHAR(120)
    """)

    cur.execute("""
        ALTER TABLE users
        ADD COLUMN IF NOT EXISTS referred_by INTEGER
    """)

    cur.execute("""
        ALTER TABLE users
        ADD COLUMN IF NOT EXISTS referral_code VARCHAR(50)
    """)

    con.commit()
    cur.close()
    con.close()


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            flash("Please login to continue.", "error")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated



def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        admin_id = session.get("admin_user_id")
        if not admin_id:
            return redirect(url_for("admin_login"))

        con = get_db()
        cur = con.cursor()
        try:
            cur.execute(
                "SELECT is_admin FROM users WHERE id=%s",
                (admin_id,)
            )
            role = cur.fetchone()
            if not role or not role[0]:
                session.pop("admin_user_id", None)
                return redirect(url_for("admin_login"))
        finally:
            cur.close()
            con.close()

        return f(*args, **kwargs)
    return decorated


@app.route("/")
def home():
    return render_template("index.html")



@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        fullname = request.form.get("fullname", "").strip()
        email = request.form.get("email", "").strip().lower()
        username = request.form.get("username", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")
        referral_code = (
            request.form.get("referral_code", "").strip().upper()
            or request.args.get("ref", "").strip().upper()
        )

        if not all([fullname, email, username, password, confirm]):
            flash("Please complete all fields.", "error")
            return redirect(url_for("register"))

        if len(fullname) > 120:
            flash("Full name is too long.", "error")
            return redirect(url_for("register"))

        if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            flash("Enter a valid email address.", "error")
            return redirect(url_for("register"))

        if not re.fullmatch(r"[a-z0-9_]{3,30}", username):
            flash("Username must be 3-30 characters using letters, numbers or underscores.", "error")
            return redirect(url_for("register"))

        if len(password) < 8:
            flash("Password must contain at least 8 characters.", "error")
            return redirect(url_for("register"))

        if password != confirm:
            flash("Passwords do not match.", "error")
            return redirect(url_for("register"))

        password_hash = generate_password_hash(password)
        con = get_db()
        cur = con.cursor()

        try:
            referred_by = None

            if referral_code:
                cur.execute(
                    "SELECT id FROM users WHERE UPPER(referral_code)=%s",
                    (referral_code,)
                )
                referrer = cur.fetchone()

                if not referrer:
                    flash("Invalid referral code. Please check the link.", "error")
                    return redirect(url_for("register"))

                referred_by = referrer[0]

            cur.execute("""
                INSERT INTO users
                (name, username, email, password, full_name, fullname,
                 password_hash, referred_by)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
            """, (
                fullname, username, email, password_hash,
                fullname, fullname, password_hash, referred_by
            ))

            user_id = cur.fetchone()[0]
            con.commit()

            session.clear()
            session["user_id"] = user_id
            session["username"] = username
            session["fullname"] = fullname

            return redirect(url_for("dashboard"))

        except psycopg2.errors.UniqueViolation:
            con.rollback()
            flash("Email or username already exists.", "error")
            return redirect(url_for("register"))

        except Exception:
            con.rollback()
            app.logger.exception("Registration failed")
            flash("Registration failed. Please try again.", "error")
            return redirect(url_for("register"))

        finally:
            cur.close()
            con.close()

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        identity = request.form.get("identity", "").strip().lower()
        password = request.form.get("password", "")

        con = get_db()
        cur = con.cursor()

        cur.execute("""
            SELECT id, fullname, username, password_hash
            FROM users
            WHERE email = %s OR username = %s
        """, (identity, identity))

        user = cur.fetchone()

        cur.close()
        con.close()

        if user and check_password_hash(user[3], password):

            session.clear()
            session["user_id"] = user[0]
            session["fullname"] = user[1]
            session["username"] = user[2]

            return redirect(url_for("dashboard"))

        flash("Incorrect username, email or password.", "error")
        return redirect(url_for("login"))

    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():

    con = get_db()
    cur = con.cursor()

    cur.execute(
        "SELECT balance FROM users WHERE id = %s FOR UPDATE",
        (session["user_id"],)
    )

    result = cur.fetchone()
    cur.execute("SELECT balance FROM users WHERE id=%s",
                (session["user_id"],))
    result = cur.fetchone()
    cur.execute("""
        SELECT id, plan_name, daily_reward, days_paid,
               next_reward_at, status,
               (next_reward_at <= CURRENT_TIMESTAMP) AS claim_ready
        FROM farm_activations
        WHERE user_id=%s AND status='active' AND days_paid < 30
        ORDER BY activated_at DESC LIMIT 1
    """, (session["user_id"],))
    active_plan = cur.fetchone()
    con.commit()

    cur.close()
    con.close()

    if not result:
        session.clear()
        return redirect(url_for("login"))

    return render_template(
        "dashboard.html",
        fullname=session["fullname"],
        username=session["username"],
        balance=result[0],
        active_plan=active_plan
    )




# ---------------- FARM ACCOUNT FEATURES ----------------

PLANS = {
    "starter": {"name": "STARTER", "capital": 1000, "daily": 200},
    "small": {"name": "SMALL", "capital": 2000, "daily": 300},
    "medium": {"name": "MEDIUM", "capital": 5000, "daily": 400},
    "big": {"name": "BIG SEED", "capital": 10000, "daily": 700},
}


def feature_page(title, content):
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{ title }} | Kellie's Green Farms</title>

    <style>
    *{box-sizing:border-box;margin:0;padding:0}

    body{
        min-height:100vh;
        font-family:Arial,sans-serif;
        color:#fff;
        background:
        radial-gradient(ellipse at 15% 10%,#0c5935 0%,transparent 40%),
        radial-gradient(ellipse at 90% 90%,#07502e 0%,transparent 40%),
        #02150d;
        display:flex;
        justify-content:center;
        align-items:center;
        padding:22px;
        overflow-x:hidden;
    }

    .glow{
        position:fixed;
        width:250px;
        height:250px;
        border-radius:50%;
        background:#20ff82;
        filter:blur(110px);
        opacity:.12;
        pointer-events:none;
        animation:float 6s ease-in-out infinite alternate;
    }

    @keyframes float{
        from{transform:translate(-30px,-20px)}
        to{transform:translate(50px,40px)}
    }

    .container{
        width:100%;
        max-width:480px;
        position:relative;
        z-index:1;
    }

    .brand{
        text-align:center;
        color:#39ff91;
        font-size:13px;
        font-weight:bold;
        letter-spacing:2px;
        margin-bottom:22px;
        text-shadow:0 0 15px #24f58a88;
    }

    .card{
        background:linear-gradient(145deg,#0b3020,#061d13);
        border:1px solid #32ff9566;
        border-radius:22px;
        padding:30px 25px;
        box-shadow:
        0 0 15px #24f58a20,
        0 0 45px #24f58a13,
        inset 0 0 25px #24f58a08;
    }

    .icon{
        width:65px;
        height:65px;
        display:flex;
        justify-content:center;
        align-items:center;
        margin:0 auto 20px;
        border-radius:20px;
        background:#0d4a2c;
        border:1px solid #35ff9566;
        font-size:30px;
        box-shadow:0 0 25px #24f58a30;
    }

    h1{
        text-align:center;
        color:#39ff91;
        font-size:27px;
        margin-bottom:10px;
        text-shadow:0 0 18px #24f58a55;
    }

    .subtitle{
        text-align:center;
        color:#a9c9b5;
        font-size:13px;
        line-height:1.7;
        margin-bottom:27px;
    }

    .form-content input{
        display:block;
        width:100%;
        padding:16px;
        margin:13px 0;
        background:#03190f;
        border:1px solid #286b49;
        border-radius:11px;
        color:white;
        outline:none;
        font-size:15px;
        transition:.25s;
    }

    .form-content input:focus{
        border-color:#39ff91;
        box-shadow:0 0 5px #24f58a,0 0 17px #24f58a35;
    }

    .form-content input::placeholder{color:#789987}

    .form-content button{
        width:100%;
        border:0;
        border-radius:11px;
        padding:16px;
        margin-top:12px;
        color:#032012;
        background:linear-gradient(100deg,#20e879,#65ffac);
        font-size:15px;
        font-weight:bold;
        cursor:pointer;
        box-shadow:0 0 18px #24f58a55;
        transition:.25s;
    }

    .form-content button:hover{
        transform:translateY(-2px);
        box-shadow:0 0 28px #24f58a99;
    }

    .form-content p{
        color:#c1d8ca;
        font-size:13px;
        line-height:1.8;
        margin:12px 0;
    }

    .info{
        margin-top:20px;
        padding:14px;
        background:#03190f;
        border:1px solid #24f58a30;
        border-radius:11px;
        color:#a9c9b5;
        font-size:12px;
        line-height:1.7;
    }

    .back{
        display:block;
        text-align:center;
        margin-top:22px;
        color:#39ff91;
        text-decoration:none;
        font-size:14px;
    }

    .back:hover{text-shadow:0 0 12px #24f58a}

    @media(max-width:420px){
        .card{padding:25px 18px}
        h1{font-size:24px}
    }
    </style>
    </head>

    <body>
    <div class="glow"></div>

    <div class="container">
        <div class="brand">🌱 KELLIE'S GREEN FARMS</div>

        <div class="card">
            {% if 'Deposit' not in title %}
            <div class="icon">
                {% if 'Withdrawal' in title %}💸{% else %}🌱{% endif %}
            </div>
            <h1>{{ title }}</h1>
            <p class="subtitle">Manage your farm account securely.</p>
            {% endif %}

            <div class="form-content">
                {{ content|safe }}
            </div>

            <div class="info">
                🔒 Your account requests are recorded for review.
                Deposits and withdrawals remain pending until verified
                or approved.
            </div>

            <a class="back" href="/dashboard">← Back to Dashboard</a>
        </div>
    </div>
    </body>
    </html>
    """, title=title, content=content)



@app.route("/deposit", methods=["GET", "POST"])
@login_required
def deposit():
    if request.method == "POST":
        try:
            amount = float(request.form.get("amount", "0"))
        except ValueError:
            amount = 0

        sender = request.form.get("sender", "").strip()

        if amount < 1000 or not sender:
            return feature_page("Deposit", """
            <h2>Invalid deposit details</h2>
            <p>Enter your sender name and an amount of at least ₦1,000.</p>
            <a href="/deposit">Try again</a>
            """)

        con = get_db()
        cur = con.cursor()
        try:
            cur.execute("""
                INSERT INTO farm_transactions
                (user_id, transaction_type, amount, status, description)
                VALUES (%s, 'deposit', %s, 'pending', %s)
            """, (
                session["user_id"],
                amount,
                "Deposit from " + sender
            ))
            con.commit()
        except Exception:
            con.rollback()
            raise
        finally:
            cur.close()
            con.close()

        return feature_page("Deposit submitted", """
        <h2>Deposit request submitted!</h2>
        <p>Your payment is awaiting administrator verification.</p>
        <p>Your balance will only change after approval.</p>
        <a href="/dashboard">Back to Dashboard</a>
        """)


    return feature_page("Deposit", """
    <style>
    .pay-wrap{max-width:650px;margin:0 auto;color:#eaffef}
    .pay-heading{text-align:center;margin-bottom:25px}
    .pay-heading .icon{
        width:65px;height:65px;margin:0 auto 15px;
        display:grid;place-items:center;border-radius:20px;
        background:#123c27;border:1px solid #36dc79;font-size:30px;
    }
    .pay-heading h2{color:#43f58c;font-size:27px;margin:8px 0}
    .pay-heading p{color:#a9c8b5;font-size:14px}
    .account-card{
        background:linear-gradient(145deg,#103c26,#071d12);
        border:1px solid #35d978;border-radius:20px;
        padding:23px;margin:22px 0;
        box-shadow:0 10px 30px #00d66a18;
    }
    .account-label{font-size:11px;letter-spacing:2px;color:#9bc9aa}
    .bank-name{font-size:27px;font-weight:800;margin:12px 0 25px;color:#ffffff;border-bottom:1px solid #ffffff30;padding-bottom:18px}.bank-name span{display:block;font-size:10px;letter-spacing:2px;color:#80e8aa;margin-top:8px}
    .account-number{
        font-size:29px;font-weight:800;letter-spacing:2px;
        color:#65ffa0;margin:10px 0;
        overflow-wrap:anywhere;
    }
    .account-name{font-size:18px;font-weight:bold;margin-top:9px}
    .copy-btn{
        width:100%;padding:13px;margin-top:18px;
        background:#174e30;color:#75ffa5;
        border:1px solid #35d978;border-radius:11px;
        font-weight:bold;font-size:14px;
    }
    .payment-note{
        background:#142d1e;border-left:4px solid #42e987;
        padding:13px;border-radius:9px;
        color:#c5e4ce;font-size:13px;line-height:1.6;
        margin:18px 0;
    }
    .form-card{
        background:#0b2115;border:1px solid #245b3a;
        padding:21px;border-radius:18px;margin-top:20px;
    }
    .form-card h3{margin-top:0;color:#6bffa0}
    .field-label{display:block;color:#c9e5d1;font-size:13px;
        margin:17px 0 8px;font-weight:bold}
    .pay-input{
        width:100%;padding:16px;border-radius:11px;
        border:1px solid #326b48;background:#06170e;
        color:white;font-size:16px;outline:none;
    }
    .pay-input:focus{border-color:#42ed89}
    .submit-payment{
        width:100%;padding:16px;margin-top:22px;
        border:0;border-radius:12px;
        background:linear-gradient(100deg,#13d976,#62ffac);
        color:#052313;font-weight:800;font-size:16px;
        cursor:pointer;
    }
    .secure-note{text-align:center;color:#9bb9a5;
        font-size:12px;line-height:1.7;margin-top:17px}
    </style>

    <div class="pay-wrap">
      <div class="pay-heading">
        <div class="icon">💳</div>
        <h2>Make Your Deposit</h2>
        <p>Fund your farm account using the payment details below.</p>
      </div>

      <div class="account-card">
        <div class="account-label">BANK TRANSFER DETAILS</div>
        <div class="bank-name">PalmPay<span>OFFICIAL PAYMENT DETAILS</span></div>

        <div class="account-label">ACCOUNT NUMBER</div>
        <div class="account-number" id="farmAccount">9064525172</div>

        <div class="account-label">ACCOUNT NAME</div>
        <div class="account-name">Arinze Michael Ogbuinya</div>

        <button type="button" class="copy-btn"
          onclick="copyFarmAccount()">Copy Account Number</button>
      </div>

      <div class="payment-note">
        <strong>Important:</strong> Transfer your chosen amount to the
        PalmPay account above. After making payment, enter the exact
        sender account name and amount below.
      </div>

      <div class="form-card">
        <h3>Payment Confirmation</h3>
        <p style="color:#a9c8b5;font-size:13px">
          Complete these details after transferring your money.
        </p>

        <form method="POST">
          <label class="field-label">Sender's Account Name</label>
          <input class="pay-input" name="sender"
            placeholder="Enter name used for the transfer" required>

          <label class="field-label">Amount Deposited (₦)</label>
          <input class="pay-input" name="amount" type="number"
            min="1000" step="1" placeholder="Enter deposit amount"
            required>

          <button class="submit-payment" type="submit">
            SUBMIT DEPOSIT
          </button>
        </form>
      </div>

      <div class="secure-note">
        🔒 Your deposit request will be reviewed by the administrator.
        <br>Minimum deposit: ₦1,000.
        <br>Your balance is credited only after approval.
      </div>
    </div>

    <script>
    function copyFarmAccount(){
        const number = "9064525172";
        if(navigator.clipboard && window.isSecureContext){
            navigator.clipboard.writeText(number).then(
                () => alert("Account number copied successfully!")
            );
        }else{
            const input=document.createElement("textarea");
            input.value=number;
            document.body.appendChild(input);
            input.select();
            document.execCommand("copy");
            input.remove();
            alert("Account number copied!");
        }
    }
    </script>
    """)

@app.route("/withdraw", methods=["GET", "POST"])
@login_required
def withdraw():
    if request.method == "POST":
        try:
            amount = float(request.form.get("amount", "0"))
        except ValueError:
            amount = 0

        account = request.form.get("account", "").strip()
        bank = request.form.get("bank", "").strip()
        account_name = request.form.get("account_name", "").strip()

        if amount < 1000 or not all([account, bank, account_name]):
            return feature_page("Withdrawal", """
            <p>Complete all fields. Minimum withdrawal is ₦1,000.</p>
            """)

        con = get_db()
        cur = con.cursor()
        cur.execute("SELECT balance FROM users WHERE id=%s FOR UPDATE",
                    (session["user_id"],))
        row = cur.fetchone()

        if not row or float(row[0]) < amount:
            cur.close()
            con.close()
            return feature_page("Withdrawal", "<p>Insufficient available balance.</p>")

        # Deduct immediately when the withdrawal request is submitted.
        cur.execute("""
            UPDATE users
            SET balance=balance-%s
            WHERE id=%s AND balance >= %s
        """, (amount, session["user_id"], amount))

        if cur.rowcount != 1:
            con.rollback()
            cur.close()
            con.close()
            return feature_page("Withdrawal", "<p>Insufficient available balance.</p>")

        cur.execute("""
            INSERT INTO farm_transactions
            (user_id, transaction_type, amount, status, description)
            VALUES (%s, 'withdrawal', %s, 'pending', %s)
        """, (session["user_id"], amount,
              "Bank: " + bank + "; Account: " + account +
              "; Name: " + account_name))

        con.commit()
        cur.close()
        con.close()

        return feature_page("Withdrawal submitted", """
        <p>Your withdrawal request is pending review.</p>
        <p>Your balance remains unchanged until the request is approved.</p>
        """)

    return feature_page("Withdrawal", """
    <form method="POST">
    <input name="account_name" placeholder="Account name" required>
    <input name="account" placeholder="Account number" required>
    <input name="bank" placeholder="Bank name" required>
    <input name="amount" type="number" min="1000" placeholder="Amount" required>
    <button type="submit">Submit Withdrawal</button>
    </form><p>Minimum withdrawal: ₦1,000.</p>
    """)



@app.route("/referrals")
@login_required
def referrals():
    import html

    con = get_db()
    cur = con.cursor()

    cur.execute(
        "SELECT referral_code FROM users WHERE id=%s",
        (session["user_id"],)
    )
    row = cur.fetchone()
    code = row[0] if row else None

    if not code:
        code = secrets.token_hex(5).upper()
        cur.execute(
            "UPDATE users SET referral_code=%s WHERE id=%s",
            (code, session["user_id"])
        )
        con.commit()

    link = request.url_root.rstrip("/") + "/register?ref=" + code

    cur.execute(
        "SELECT COUNT(*) FROM users WHERE referred_by=%s",
        (session["user_id"],)
    )
    count = cur.fetchone()[0]

    cur.close()
    con.close()

    safe_code = html.escape(str(code))
    safe_link = html.escape(link, quote=True)

    content = f"""
    <style>
    .ref-card{{
        background:linear-gradient(135deg,#0b5130,#06301e);
        border:1px solid #39ff91;
        border-radius:16px;padding:22px;
        text-align:center;
        box-shadow:0 0 22px #24f58a30;
        margin:18px 0;
    }}
    .ref-number{{
        font-size:35px;font-weight:bold;
        color:#48ff9c;margin:12px 0;
        text-shadow:0 0 15px #24f58a66;
    }}
    .ref-link{{
        background:#03190f;padding:14px;
        border:1px solid #39ff9166;
        border-radius:10px;overflow-wrap:anywhere;
        color:#baffd4;font-size:13px;
        margin:15px 0;
    }}
    .copy-btn,.share-btn{{
        display:block;width:100%;padding:15px;
        border:0;border-radius:10px;
        margin-top:12px;font-weight:bold;
        text-align:center;text-decoration:none;
        cursor:pointer;font-size:14px;
    }}
    .copy-btn{{background:#39ff91;color:#032012}}
    .share-btn{{background:#075e36;color:white;
        border:1px solid #39ff91}}
    .ref-small{{color:#a9c9b5;font-size:12px;
        line-height:1.8;margin-top:15px}}
    </style>

    <div class="ref-card">
        <div style="font-size:32px">👥</div>
        <p>Your registered referrals</p>
        <div class="ref-number">{count}</div>
        <p>People who registered using your referral code</p>
    </div>

    <p style="color:#39ff91;font-weight:bold">
        YOUR REFERRAL CODE
    </p>
    <div class="ref-link">{safe_code}</div>

    <p style="color:#39ff91;font-weight:bold;margin-top:20px">
        YOUR PERSONAL REFERRAL LINK
    </p>
    <div class="ref-link" id="referralLink">{safe_link}</div>

    <button class="copy-btn" onclick="copyReferral()">
        📋 COPY REFERRAL LINK
    </button>

    <a class="share-btn"
       href="https://wa.me/?text={safe_link}"
       target="_blank">
       🟢 SHARE ON WHATSAPP
    </a>

    <p class="ref-small">
        Share your personal link with people who may be interested
        in Kellie's Green Farms. Referral registrations are counted
        when the referral system records the registration correctly.
    </p>

    <script>
    function copyReferral(){{
        const link=document.getElementById("referralLink").innerText;
        if(navigator.clipboard && window.isSecureContext){{
            navigator.clipboard.writeText(link).then(
                ()=>alert("Referral link copied!")
            ).catch(()=>fallbackCopy(link));
        }}else{{
            fallbackCopy(link);
        }}
    }}
    function fallbackCopy(link){{
        const input=document.createElement("textarea");
        input.value=link;
        document.body.appendChild(input);
        input.select();
        document.execCommand("copy");
        input.remove();
        alert("Referral link copied!");
    }}
    </script>
    """

    return feature_page("Your Referrals", content)


@app.route("/history")
@login_required
def history():
    import html

    con = get_db()
    cur = con.cursor()

    try:
        cur.execute("""
            SELECT transaction_type, amount, status,
                   description, created_at
            FROM farm_transactions
            WHERE user_id=%s
            ORDER BY created_at DESC
            LIMIT 100
        """, (session["user_id"],))

        rows = cur.fetchall()

    finally:
        cur.close()
        con.close()

    cards = ""

    for kind, amount, status, description, created in rows:
        kind_text = html.escape(str(kind).replace("_", " ").title())
        status_text = html.escape(str(status).title())
        description_text = html.escape(str(description or "Account activity"))
        date_text = html.escape(str(created))
        amount_text = format(float(amount), ",.2f")

        status_lower = str(status).lower()
        badge_class = "done" if status_lower == "completed" else "pending"

        sign = "+" if kind == "daily_reward" and status_lower == "completed" else ""

        cards += f"""
        <div class="history-card">
            <div class="history-top">
                <div>
                    <div class="history-kind">{kind_text}</div>
                    <div class="history-description">{description_text}</div>
                </div>
                <div class="history-amount">{sign}₦{amount_text}</div>
            </div>
            <div class="history-bottom">
                <span class="badge {badge_class}">{status_text}</span>
                <span class="history-date">{date_text}</span>
            </div>
        </div>
        """

    if not cards:
        cards = """
        <div class="empty-history">
            <div style="font-size:38px">📋</div>
            <h3>No transactions yet</h3>
            <p>Your account activities will appear here.</p>
        </div>
        """

    content = f"""
    <style>
    .history-summary{{
        background:linear-gradient(130deg,#0b5130,#062719);
        border:1px solid #39ff9166;
        padding:20px;border-radius:14px;
        margin:15px 0 22px;
        box-shadow:0 0 20px #24f58a20;
    }}
    .history-summary p{{color:#b5d9c3;font-size:13px}}
    .history-card{{
        background:#03190f;
        border:1px solid #24f58a40;
        border-radius:13px;
        padding:17px;margin:13px 0;
    }}
    .history-top{{
        display:flex;justify-content:space-between;
        gap:10px;align-items:flex-start;
    }}
    .history-kind{{color:#39ff91;font-weight:bold;font-size:15px}}
    .history-description{{
        color:#a9c9b5;font-size:12px;
        margin-top:7px;line-height:1.5;
    }}
    .history-amount{{font-weight:bold;white-space:nowrap;font-size:15px}}
    .history-bottom{{
        display:flex;justify-content:space-between;
        align-items:center;margin-top:15px;gap:8px;
    }}
    .badge{{padding:6px 10px;border-radius:20px;font-size:10px;font-weight:bold}}
    .done{{background:#0d5733;color:#54ffa0}}
    .pending{{background:#573d0d;color:#ffd477}}
    .history-date{{color:#789987;font-size:10px;text-align:right}}
    .empty-history{{
        text-align:center;padding:35px 15px;
        background:#03190f;border:1px dashed #39ff9166;
        border-radius:14px;color:#a9c9b5;
    }}
    .empty-history h3{{color:#39ff91;margin:12px 0}}
    </style>

    <div class="history-summary">
        <p>📊 ACCOUNT ACTIVITY</p>
        <h2 style="color:#39ff91;margin-top:10px">Transaction History</h2>
        <p style="margin-top:8px">
            Your latest deposits, withdrawals, activations and rewards.
        </p>
    </div>

    {cards}

    <p style="color:#789987;font-size:11px;margin-top:18px">
        Showing your latest 100 recorded transactions.
    </p>
    """

    return feature_page("Account History", content)



@app.route("/activate/<plan>", methods=["GET", "POST"])
@login_required
def activate_plan(plan):
    selected = PLANS.get(plan)

    if not selected:
        return feature_page("Plan", "<p>Invalid plan selected.</p>")

    if request.method == "GET":
        return feature_page("Confirm " + selected["name"], f"""
            <p>Capital: ₦{selected['capital']:,}</p>
            <p>Illustrative daily reward: ₦{selected['daily']:,}</p>
            <p>Duration: 30 days.</p>
            <p>These are estimates, not guaranteed returns. Agricultural
            activities can result in loss of capital.</p>
            <form method="POST">
                <button type="submit">Confirm Plan Activation</button>
            </form>
        """)

    con = get_db()
    cur = con.cursor()

    try:
        cur.execute("""
            SELECT balance
            FROM users
            WHERE id=%s
            FOR UPDATE
        """, (session["user_id"],))
        row = cur.fetchone()

        if not row or float(row[0]) < selected["capital"]:
            con.rollback()
            return feature_page(
                "Insufficient balance",
                "<p>Please ensure you have sufficient verified funds.</p>"
            )

        cur.execute("""
            UPDATE users
            SET balance=balance-%s, active_plan=%s
            WHERE id=%s
        """, (selected["capital"], selected["name"], session["user_id"]))

        cur.execute("""
            INSERT INTO farm_activations
            (user_id, plan_name, capital, daily_reward, next_reward_at)
            VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP + INTERVAL '24 hours')
        """, (
            session["user_id"], selected["name"],
            selected["capital"], selected["daily"]
        ))

        cur.execute("""
            INSERT INTO farm_transactions
            (user_id, transaction_type, amount, status, description)
            VALUES (%s, 'plan_activation', %s, 'completed', %s)
        """, (
            session["user_id"], selected["capital"],
            "Activated " + selected["name"]
        ))

        # This conditional update makes the referral reward one-time only.
        cur.execute("""
            UPDATE users
            SET referral_reward_paid=TRUE
            WHERE id=%s
              AND referred_by IS NOT NULL
              AND referral_reward_paid=FALSE
            RETURNING referred_by
        """, (session["user_id"],))

        referral = cur.fetchone()

        if referral and referral[0]:
            referrer_id = referral[0]

            cur.execute("""
                UPDATE users
                SET balance=balance+750
                WHERE id=%s
            """, (referrer_id,))

            if cur.rowcount == 1:
                cur.execute("""
                    INSERT INTO farm_transactions
                    (user_id, transaction_type, amount, status, description)
                    VALUES (%s, 'referral_reward', 750, 'completed', %s)
                """, (
                    referrer_id,
                    "₦750 referral reward for first plan activation"
                ))

        con.commit()
        return redirect(url_for("dashboard"))

    except Exception:
        con.rollback()
        app.logger.exception("Plan activation failed")
        return feature_page(
            "Activation error",
            "<p>Could not activate the plan. Please try again.</p>"
        )

    finally:
        cur.close()
        con.close()


@app.route("/claim-reward/<int:activation_id>", methods=["POST"])
@login_required
def claim_reward(activation_id):
    con = get_db()
    cur = con.cursor()
    try:
        cur.execute("""
            SELECT daily_reward, days_paid, next_reward_at
            FROM farm_activations
            WHERE id=%s AND user_id=%s
              AND status='active' AND days_paid < 30
            FOR UPDATE
        """, (activation_id, session["user_id"]))

        row = cur.fetchone()
        if not row:
            con.rollback()
            return feature_page("Claim unavailable",
                "<p>No remaining rewards on this plan.</p><p><a href='/dashboard'>Dashboard</a></p>")

        reward, days_paid, next_time = row

        cur.execute("SELECT CURRENT_TIMESTAMP >= %s", (next_time,))
        if not cur.fetchone()[0]:
            con.rollback()
            return feature_page("Reward not ready",
                "<p>Your 24-hour waiting period has not ended.</p><p><a href='/dashboard'>Dashboard</a></p>")

        cur.execute(
            "UPDATE users SET balance=balance+%s WHERE id=%s",
            (reward, session["user_id"])
        )

        cur.execute("""
            UPDATE farm_activations
            SET days_paid=days_paid+1,
                next_reward_at=CURRENT_TIMESTAMP + INTERVAL '24 hours',
                status=CASE WHEN days_paid+1 >= 30
                            THEN 'completed' ELSE 'active' END
            WHERE id=%s AND user_id=%s
        """, (activation_id, session["user_id"]))

        cur.execute("""
            INSERT INTO farm_transactions
            (user_id, transaction_type, amount, status, description)
            VALUES (%s, 'daily_reward', %s, 'completed', %s)
        """, (
            session["user_id"], reward,
            f"Manual reward claim {days_paid + 1} of 30"
        ))

        con.commit()
        return redirect(url_for("dashboard", claim="success"))

    except Exception:
        con.rollback()
        app.logger.exception("Manual reward claim failed")
        return feature_page("Claim error",
            "<p>Could not process your claim. Please try again.</p><p><a href='/dashboard'>Dashboard</a></p>")
    finally:
        cur.close()
        con.close()






@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    ADMIN_USERNAME = "kellie@gmail.com"
    ADMIN_PASSWORD = "Kellie@50"

    if request.method == "POST":
        identity = request.form.get("identity", "").strip().lower()
        password = request.form.get("password", "")

        if identity == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            con = get_db()
            cur = con.cursor()
            try:
                cur.execute("""
                    SELECT id, fullname, username
                    FROM users
                    WHERE LOWER(email)=%s
                """, (ADMIN_USERNAME,))
                user = cur.fetchone()

                if not user:
                    flash("Admin account not found in the database.", "error")
                    return redirect(url_for("admin_login"))

                cur.execute(
                    "UPDATE users SET is_admin=TRUE WHERE id=%s",
                    (user[0],)
                )
                con.commit()

                session.clear()
                session["admin_user_id"] = user[0]
                session["admin_fullname"] = user[1]
                session["admin_username"] = user[2]

                return redirect(url_for("admin_dashboard"))
            finally:
                cur.close()
                con.close()

        flash("Invalid administrator login details.", "error")
        return redirect(url_for("admin_login"))

    return render_template_string("""
    <!DOCTYPE html>
    <html>
    <head>
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>Farm Admin Login</title>
      <style>
        * { box-sizing: border-box; }
        body {
          margin: 0; min-height: 100vh; display: grid;
          place-items: center; padding: 20px;
          font-family: Arial; background: linear-gradient(135deg,#052e16,#166534);
        }
        .box {
          width: 100%; max-width: 390px; padding: 30px;
          background: white; border-radius: 18px;
          box-shadow: 0 15px 45px #0005;
        }
        h2 { color: #166534; text-align: center; }
        p { color: #64748b; text-align: center; }
        input {
          width: 100%; padding: 14px; margin: 10px 0;
          border: 1px solid #cbd5e1; border-radius: 9px;
        }
        button {
          width: 100%; padding: 14px; margin-top: 12px;
          border: 0; border-radius: 9px; color: white;
          background: #15803d; font-weight: bold;
        }
        a { display: block; text-align: center; margin-top: 18px; color: #15803d; }
        .error { color: #dc2626; text-align: center; }
      </style>
    </head>
    <body>
      <form class="box" method="POST">
        <h2>🌱 Admin Portal</h2>
        <p>KELLIE'S GREEN FARMS</p>
        {% for category, message in get_flashed_messages(with_categories=true) %}
          <div class="error">{{ message }}</div>
        {% endfor %}
        <input name="identity" placeholder="Admin email or username" required>
        <input name="password" type="password" placeholder="Admin password" required>
        <button type="submit">Admin Login</button>
        <a href="/login">Customer Login</a>
      </form>
    </body>
    </html>
    """)


@app.route("/admin")
@admin_required
def admin_dashboard():
    con = get_db()
    cur = con.cursor()

    try:
        cur.execute(
            "SELECT is_admin FROM users WHERE id=%s",
            (session["admin_user_id"],)
        )
        role = cur.fetchone()

        if not role or not role[0]:
            return "Access denied: administrators only.", 403

        cur.execute(
            "SELECT COUNT(*) FROM users WHERE COALESCE(is_admin,FALSE)=FALSE"
        )
        total_users = cur.fetchone()[0]

        cur.execute("""
            SELECT
                COUNT(*) FILTER (
                    WHERE transaction_type='deposit' AND status='pending'
                ),
                COALESCE(SUM(amount) FILTER (
                    WHERE transaction_type='deposit' AND status='completed'
                ), 0),
                COUNT(*) FILTER (
                    WHERE transaction_type='withdrawal' AND status='pending'
                ),
                COALESCE(SUM(amount) FILTER (
                    WHERE transaction_type='withdrawal' AND status='completed'
                ), 0)
            FROM farm_transactions
        """)
        stats = cur.fetchone()

        cur.execute("""
            SELECT t.id, u.username, u.email, t.amount,
                   t.description, t.created_at
            FROM farm_transactions t
            JOIN users u ON u.id=t.user_id
            WHERE t.transaction_type='deposit'
              AND t.status='pending'
            ORDER BY t.created_at DESC
        """)
        deposits = cur.fetchall()

        cur.execute("""
            SELECT t.id, u.username, u.email, t.amount,
                   t.description, t.created_at
            FROM farm_transactions t
            JOIN users u ON u.id=t.user_id
            WHERE t.transaction_type='withdrawal'
              AND t.status='pending'
            ORDER BY t.created_at DESC
        """)
        withdrawals = cur.fetchall()

        return render_template_string("""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Kellie's Green Farms | Admin</title>
<style>
*{box-sizing:border-box}
body{
 margin:0;background:#06140c;color:#effff2;
 font-family:Arial,sans-serif;
}
.wrap{max-width:1150px;margin:auto;padding:22px}
.hero{
 padding:28px;border-radius:22px;
 background:linear-gradient(135deg,#103d25,#08763b);
 border:1px solid #38db78;
 box-shadow:0 0 25px #0c783b55;
}
.brand{font-size:13px;letter-spacing:3px;color:#b8ffd0}
h1{font-size:29px;margin:12px 0 5px}
.subtitle{color:#d0f5dc}
.section-title{margin:30px 0 14px}
.stats{
 display:grid;grid-template-columns:repeat(4,1fr);
 gap:14px;margin-top:22px;
}
.stat,.panel{
 background:#10271a;border:1px solid #245c39;
 border-radius:17px;padding:20px;
}
.stat small{color:#a9cbb5}
.number{font-size:29px;font-weight:bold;color:#6dff9e;margin-top:12px}
.money{font-size:22px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}
.panel h2{font-size:19px;margin-top:0}
.request{
 background:#071b10;border:1px solid #285b3b;
 padding:15px;border-radius:13px;margin-top:13px;
 overflow-wrap:anywhere;
}
.request p{line-height:1.5;color:#d2e9d9}
.muted{font-size:12px;color:#9db9a5}
button{
 width:100%;padding:12px;border:0;border-radius:9px;
 font-weight:bold;font-size:14px;cursor:pointer;margin-top:8px;
}
.approve{background:#38e879;color:#062311}
.reject{background:#e94b58;color:white}
.empty{
 padding:18px;text-align:center;color:#a9cbb5;
 background:#091c11;border-radius:12px;margin-top:12px;
}
.back{
 display:inline-block;margin-top:25px;color:#73ffa2;
 text-decoration:none;padding:12px 17px;
 border:1px solid #347b4d;border-radius:10px;
}
@media(max-width:750px){
 .stats{grid-template-columns:repeat(2,1fr)}
 .grid{grid-template-columns:1fr}
 h1{font-size:23px}
 .wrap{padding:13px}
}
@media(max-width:380px){
 .stats{grid-template-columns:1fr}
}
</style>
</head>
<body>
<div class="wrap">

 <header class="hero">
  <div class="brand">KELLIE'S GREEN FARMS</div>
  <h1>Administrator Dashboard 🌱</h1>
  <div class="subtitle">Manage customers, deposits and withdrawals.</div>
 </header>

 <h2 class="section-title">Business Overview</h2>

 <div class="stats">
  <div class="stat">
   <small>Total Customers</small>
   <div class="number">{{ total_users }}</div>
  </div>
  <div class="stat">
   <small>Pending Deposits</small>
   <div class="number">{{ stats[0] }}</div>
  </div>
  <div class="stat">
   <small>Pending Withdrawals</small>
   <div class="number">{{ stats[2] }}</div>
  </div>
  <div class="stat">
   <small>Completed Deposits</small>
   <div class="number money">₦{{ "%.2f"|format(stats[1]) }}</div>
  </div>
 </div>

 <div class="stat" style="margin-top:14px">
  <small>Total Completed Withdrawals</small>
  <div class="number money">₦{{ "%.2f"|format(stats[3]) }}</div>
 </div>

 <h2 class="section-title">Transaction Requests</h2>

 <div class="grid">
  <section class="panel">
   <h2>💰 Deposit Requests ({{ deposits|length }})</h2>
   {% for r in deposits %}
    <div class="request">
     <strong>Deposit #{{ r[0] }}</strong>
     <p>Customer: {{ r[1] }}<br>{{ r[2] }}</p>
     <p><strong>Amount: ₦{{ "%.2f"|format(r[3]) }}</strong></p>
     <p>{{ r[4] }}</p>
     <div class="muted">{{ r[5] }}</div>
     <form method="POST" action="{{ url_for('admin_transaction', transaction_id=r[0], action='approve') }}">
      <button class="approve">✓ Approve Deposit</button>
     </form>
     <form method="POST" action="{{ url_for('admin_transaction', transaction_id=r[0], action='reject') }}">
      <button class="reject">✕ Reject Deposit</button>
     </form>
    </div>
   {% else %}
    <div class="empty">No pending deposit requests.</div>
   {% endfor %}
  </section>

  <section class="panel">
   <h2>🏦 Withdrawal Requests ({{ withdrawals|length }})</h2>
   {% for r in withdrawals %}
    <div class="request">
     <strong>Withdrawal #{{ r[0] }}</strong>
     <p>Customer: {{ r[1] }}<br>{{ r[2] }}</p>
     <p><strong>Amount: ₦{{ "%.2f"|format(r[3]) }}</strong></p>
     <p>{{ r[4] }}</p>
     <div class="muted">{{ r[5] }}</div>
     <form method="POST" action="{{ url_for('admin_transaction', transaction_id=r[0], action='approve') }}">
      <button class="approve">✓ Approve Withdrawal</button>
     </form>
     <form method="POST" action="{{ url_for('admin_transaction', transaction_id=r[0], action='reject') }}">
      <button class="reject">✕ Reject Withdrawal</button>
     </form>
    </div>
   {% else %}
    <div class="empty">No pending withdrawal requests.</div>
   {% endfor %}
  </section>
 </div>

 <a class="back" href="{{ url_for('dashboard') }}">← Back to Website</a>
</div>
</body>
</html>
        """, total_users=total_users, stats=stats,
             deposits=deposits, withdrawals=withdrawals)

    finally:
        cur.close()
        con.close()



@app.route("/admin/transaction/<int:transaction_id>/<action>", methods=["POST"])
@admin_required
def admin_transaction(transaction_id, action):
    if action not in ("approve", "reject"):
        return "Invalid action", 400

    con = get_db()
    cur = con.cursor()

    try:
        cur.execute("SELECT is_admin FROM users WHERE id=%s", (session["admin_user_id"],))
        role = cur.fetchone()

        if not role or not role[0]:
            return "Access denied", 403

        cur.execute("""
            SELECT id, user_id, transaction_type, amount, status
            FROM farm_transactions
            WHERE id=%s FOR UPDATE
        """, (transaction_id,))
        tx = cur.fetchone()

        if not tx or tx[4] != "pending":
            con.rollback()
            return "Request not found or already processed.", 400

        tx_id, user_id, tx_type, amount, status = tx

        if tx_type not in ("deposit", "withdrawal"):
            con.rollback()
            return "Invalid transaction type.", 400

        cur.execute("SELECT balance FROM users WHERE id=%s FOR UPDATE", (user_id,))
        user = cur.fetchone()

        if not user:
            con.rollback()
            return "User not found.", 404

        if action == "approve":
            if tx_type == "deposit":
                cur.execute(
                    "UPDATE users SET balance=balance+%s WHERE id=%s",
                    (amount, user_id)
                )
            # Withdrawal was already deducted when the user submitted it.
            # Approval only changes its status; do not deduct again.
            new_status = "completed"
        else:
            # Refund a rejected withdrawal.
            if tx_type == "withdrawal":
                cur.execute(
                    "UPDATE users SET balance=balance+%s WHERE id=%s",
                    (amount, user_id)
                )

            new_status = "rejected"

        cur.execute("""
            UPDATE farm_transactions
            SET status=%s
            WHERE id=%s AND status='pending'
        """, (new_status, tx_id))

        if cur.rowcount != 1:
            con.rollback()
            return "Request already processed.", 409

        con.commit()
        return redirect(url_for("admin_dashboard"))

    except Exception:
        con.rollback()
        raise
    finally:
        cur.close()
        con.close()



@app.route("/admin/logout")
def admin_logout():
    session.pop("admin_user_id", None)
    session.pop("admin_fullname", None)
    session.pop("admin_username", None)
    return redirect(url_for("admin_login"))


@app.route("/logout")
def logout():
    session.clear()
    flash("You have logged out successfully.", "success")
    return redirect(url_for("login"))




# Initialize the database when Gunicorn imports this application.
init_db()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
