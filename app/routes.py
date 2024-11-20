from flask import render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, current_user, login_required
from app.models import User
from app import app, db, bcrypt, login_manager
from app.forms import RegistrationForm, LoginForm, UpdateAccountForm


# Загрузка пользователя для Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
@app.route('/home')
def home():
    return render_template('home.html')

# Маршрут регистрации
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('account'))  # Перенаправление на аккаунт, если пользователь уже аутентифицирован
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(user)
        try:
            db.session.commit()
            flash('Вы успешно зарегистрировались! Теперь вы можете войти.', 'success')
            return redirect(url_for('login'))
        except:
            db.session.rollback()
            flash('Произошла ошибка при регистрации. Возможно, email или username уже существуют.', 'danger')
    return render_template('register.html', form=form, title='Регистрация')


# Маршрут логина
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('account'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            flash('Вы вошли в систему.', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('account'))
        else:
            flash('Неверный email или пароль.', 'danger')
    return render_template('login.html', form=form, title='Вход')


# Маршрут выхода
@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы вышли из системы.', 'info')
    return redirect(url_for('login'))


# Маршрут аккаунта
@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    form = UpdateAccountForm()
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.email = form.email.data
        if form.password.data:  # Обновление пароля только если указан
            current_user.password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        db.session.commit()
        flash('Ваш профиль был обновлен!', 'success')
        return redirect(url_for('account'))
    elif request.method == 'GET':  # Заполняем форму текущими данными пользователя
        form.username.data = current_user.username
        form.email.data = current_user.email

    return render_template('account.html', title='Аккаунт', form=form)


@app.route('/delete_account', methods=['POST'])
@login_required
def delete_account():
    user = current_user
    db.session.delete(user)
    db.session.commit()
    flash('Ваш аккаунт был удален.', 'info')
    return redirect(url_for('home'))
