from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import UserMixin, login_manager, login_user, login_required, logout_user, LoginManager
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = 'qwertyuiop[56784nfu94fk48gh6gj8g5j8'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///shoes_shop.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
login_manager = LoginManager()
login_manager.init_app(app)
db = SQLAlchemy(app)



class Shoes(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Integer, nullable=False)
    isActived = db.Column(db.Boolean, default=True)
    descript = db.Column(db.Text, nullable=False)

    def __repr__(self):
        return self.title


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.String(128), nullable=False, unique=True)
    password = db.Column(db.String(256), nullable=False)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


@app.route('/')
def index():
    shoes = Shoes.query.order_by(Shoes.price).all()
    return render_template('index.html', data=shoes)


@app.route('/about')
@login_required
def about():
    return render_template('about.html')


@app.route('/create', methods=['POST', 'GET'])
def create():
    list_shoes = Shoes.query.order_by(Shoes.price).all()
    if request.method == "POST":
        title = request.form['title']
        price = request.form['price']
        descript = request.form['descript']

        list_shoe = Shoes(title=title, price=price, descript=descript)

        try:
            db.session.add(list_shoe)
            db.session.commit()
            return redirect('/create')
        except:
            flash("Проверьте правильность ввода данных")
    else:
        return render_template('create.html', data=list_shoes)


@app.route('/login', methods=['POST', 'GET'])
def login_page():
    login = request.form.get('login')
    password = request.form.get('password')
    if login == 'admin' and password == 'admin':
        return redirect('/create')
    else:
        if login and password:
            user = User.query.filter_by(login=login).first()
            if user and check_password_hash(user.password, password):
                login_user(user)
                try:
                    next_page = request.args.get('next')
                    return redirect(next_page)
                except:
                    return render_template('index.html')
            else:
                flash("Введен неправильный логин или пароль")
        else:
            flash("Заполните поля логин или пароль")
        return render_template('login.html')


@app.route('/logout', methods=['POST', 'GET'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login_page'))


@app.route('/registry', methods=['POST', 'GET'])
def registry():
    login = request.form.get('login')
    password = request.form.get('password')
    password2 = request.form.get('password2')

    if request.method == 'POST':
        if not (login or password or password2):
            flash("Заполните поля регистрации")
        elif password != password2:
            flash("Пароли не совпадают")
        else:
            password_hash = generate_password_hash(password)
            new_user = User(login=login, password=password_hash)
            db.session.add(new_user)
            db.session.commit()

            return redirect(url_for('login_page'))

    return render_template('registry.html')


@app.after_request
def redirect_to_signin(response):
    if response.status_code == 401:
        return redirect(url_for('login_page') + '?next=' + request.url)
    return response


if __name__ == "__main__":
    app.run(debug=True)
