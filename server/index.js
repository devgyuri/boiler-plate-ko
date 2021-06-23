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
    // 회원 가입 할 때 필요한 정보들을 clinet에서 가져오면 그것들을 데이터 베이스에 넣어준다
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

app.post('/api/users/login', (req, res) => { // 왜 api/users/login은 안될까?
    // 1. 데이터 베이스에서 요청한 이메일 찾기
    User.findOne({ email: req.body.email }, (err, user) => {
        if(!user) { // 해당 이메일이 없으면
            return res.json({
                loginSuccess: false,
                message: "등록되지 않은 이메일 주소입니다."
            })
        }

        // 2. 요청된 이메일이 DB에 있다면 비밀번호가 일치하는지 확인
        user.comparePassword(req.body.password, (err, isMatch) => {
            if(!isMatch)
                return res.json({
                    loginSuccess: false,
                    message: "잘못된 비밀번호입니다."
                })

            // 3. 비밀번호가 일치한다면 Token 생성
            user.generateToken((err, user) => {
                if(err)
                    return res.status(400).send(err);

                // token을 저장: cookie, or local storage, or session, ...
                res.cookie("x_auth", user.token)
                .status(200)
                .json({ loginSuccess: true, usrId: user._id })
            })
        })
    })
})

app.get('/api/users/auth', auth, (req, res) => {
    // 여기까지 미들웨어 통과했으면 Authentication이 True
    res.status(200).json({
        _id: req.user._id,
        isAdmin: req.user.role === 0 ? false : true, // role 0 -> 일반      role 1 -> admin
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