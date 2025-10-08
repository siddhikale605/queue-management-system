from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///queue.db'
app.config['SECRET_KEY'] = 'yoursecretkey'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# ---------------- Models ----------------
class Queue(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    token_number = db.Column(db.Integer, unique=True)
    status = db.Column(db.String(20), default="Waiting")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Reservation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    phone = db.Column(db.String(15))
    service = db.Column(db.String(100))
    date = db.Column(db.String(20))
    time = db.Column(db.String(20))
    token_no = db.Column(db.Integer, unique=True)
    status = db.Column(db.String(20), default="Pending")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Admin(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(200))

@login_manager.user_loader
def load_user(user_id):
    return Admin.query.get(int(user_id))

# ---------------- Auth Routes ----------------
@app.route("/login", methods=["GET","POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        admin = Admin.query.filter_by(username=username).first()
        if admin and bcrypt.check_password_hash(admin.password, password):
            login_user(admin)
            return redirect("/admin")
        else:
            flash("Invalid credentials", "danger")
    return render_template("login.html")

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("/")

# ---------------- Queue Routes ----------------
@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        name = request.form['name']
        last_token = db.session.query(db.func.max(Queue.token_number)).scalar()
        next_token = 1 if last_token is None else last_token + 1
        new_entry = Queue(name=name, token_number=next_token)
        db.session.add(new_entry)
        db.session.commit()
        return redirect(url_for('status', token=next_token))
    return render_template('home.html')

@app.route('/status/<int:token>')
def status(token):
    person = Queue.query.filter_by(token_number=token).first()
    waiting_count = Queue.query.filter(Queue.token_number < token, Queue.status=="Waiting").count()
    return render_template('status.html', person=person, waiting_count=waiting_count)

@app.route('/next')
@login_required
def next_customer():
    person = Queue.query.filter_by(status="Waiting").first()
    if person:
        person.status = "Served"
        db.session.commit()
    return redirect(url_for('admin'))

# ---------------- Reservation Routes ----------------
@app.route('/reserve', methods=['GET', 'POST'])
def reserve():
    if request.method == 'POST':
        name = request.form['name']
        phone = request.form['phone']
        service = request.form['service']
        date = request.form['date']
        time = request.form['time']

        last_res = Reservation.query.order_by(Reservation.id.desc()).first()
        next_token = 1 if not last_res else last_res.token_no + 1

        new_res = Reservation(
            name=name, phone=phone, service=service,
            date=date, time=time, token_no=next_token
        )
        db.session.add(new_res)
        db.session.commit()
        flash(f"Reservation Successful! Your Token No is {next_token}", "success")
        return redirect(url_for('reserve_status', token=next_token))
    return render_template('reserve.html')

@app.route('/reserve/status')
def reserve_status():
    token = request.args.get('token')
    if token:
        reservation = Reservation.query.filter_by(token_no=token).first()
        if reservation:
            return render_template('reserve_status.html', reservation=reservation)
        else:
            flash("Invalid Token Number", "danger")
    return render_template('reserve_status.html')

# ---------------- Admin Panel ----------------
@app.route('/admin')
@login_required
def admin():
    queue = Queue.query.filter_by(status="Waiting").all()
    reservations = Reservation.query.order_by(Reservation.created_at.desc()).all()
    return render_template('admin.html', queue=queue, reservations=reservations)
@app.route('/update_reservation/<int:id>/<action>')
@login_required
def update_reservation(id, action):
    reservation = Reservation.query.get_or_404(id)
    if action == "approve":
        reservation.status = "Approved"
    elif action == "reject":
        reservation.status = "Rejected"
    db.session.commit()
    flash(f"Reservation {action.capitalize()}d successfully!", "info")
    return redirect(url_for('admin'))

# ---------------- Run App ----------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Create default admin if not exists
        if not Admin.query.filter_by(username="admin").first():
            hashed_pw = bcrypt.generate_password_hash("admin123").decode('utf-8')
            admin = Admin(username="admin", password=hashed_pw)
            db.session.add(admin)
            db.session.commit()
    app.run(debug=True)
