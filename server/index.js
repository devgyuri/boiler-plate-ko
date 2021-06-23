const express = require('express')
const app = express()
const port = 5000
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser')
const config = require('./config/key');

const { auth } = require('./middleware/auth');
const { User } = require("./models/User");

// application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({ extended: true }));

// application/json
app.use(bodyParser.json());
app.use(cookieParser());

const mongoose = require('mongoose')
mongoose.connect(config.mongoURI, {
    useNewUrlParser: true, useUnifiedTopology: true, useCreateIndex: true, useFindAndModify: false
}).then(() => console.log('MongoDB Connected...'))
    .catch(err => console.log(err))

app.get('/', (req, res) => res.send('Hello World!'))

app.get('/api/hello', (req, res) => {
    res.send("Hello, Gyuri!")
})

app.post('/api/users/register', (req, res) => {
    // ȸ�� ���� �� �� �ʿ��� �������� clinet���� �������� �װ͵��� ������ ���̽��� �־��ش�
    const user = new User(req.body)

    user.save((err, doc) => {
        if(err) return res.json({
            success: false,
            err
        })
        return res.status(200).json({
            succcess: true
        })
    })
})

app.post('/api/users/login', (req, res) => { // �� api/users/login�� �ȵɱ�?
    // 1. ������ ���̽����� ��û�� �̸��� ã��
    User.findOne({ email: req.body.email }, (err, user) => {
        if(!user) { // �ش� �̸����� ������
            return res.json({
                loginSuccess: false,
                message: "��ϵ��� ���� �̸��� �ּ��Դϴ�."
            })
        }

        // 2. ��û�� �̸����� DB�� �ִٸ� ��й�ȣ�� ��ġ�ϴ��� Ȯ��
        user.comparePassword(req.body.password, (err, isMatch) => {
            if(!isMatch)
                return res.json({
                    loginSuccess: false,
                    message: "�߸��� ��й�ȣ�Դϴ�."
                })

            // 3. ��й�ȣ�� ��ġ�Ѵٸ� Token ����
            user.generateToken((err, user) => {
                if(err)
                    return res.status(400).send(err);

                // token�� ����: cookie, or local storage, or session, ...
                res.cookie("x_auth", user.token)
                .status(200)
                .json({ loginSuccess: true, usrId: user._id })
            })
        })
    })
})

app.get('/api/users/auth', auth, (req, res) => {
    // ������� �̵���� ��������� Authentication�� True
    res.status(200).json({
        _id: req.user._id,
        isAdmin: req.user.role === 0 ? false : true, // role 0 -> �Ϲ�      role 1 -> admin
        isAuth: true,
        email: req.user.email,
        name: req.user.name,
        lastname: req.user.lastname,
        role: req.user.role,
        image: req.user.image,
    })
})

app.get('/api/users/logout', auth, (req, res) => {
    User.findOneAndUpdate({ _id: req.user._id }, { token: "" }, (err, user) => {
        if(err)
            return res.json({
                success: false, err
            });

        return res.status(200).send({
            sucess: true
        });
    })
})

app.listen(port, () => console.log(`Example app listenig on port ${port}!`))