const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken');
const saltRounds = 10

const userSchema = mongoose.Schema({
    name: {
        type: String,
        maxlength: 50
    },
    email: {
        type: String,
        trim: true, // remove space
        unique: 1
    },
    password: {
        type: String,
        minlength: 5
    },
    lastname: {
        type: String,
        default: 0
    },
    role: {
        type: Number,
        default: 0
    },
    image: String,
    token: {
        type: String
    },
    tokenExp: {
        type: Number
    }
})

userSchema.pre('save', function(next) {
    var user = this;

    if(user.isModified('password')) { // 비밀번호 변경시
        // 비밀번호 암호화
        bcrypt.genSalt(saltRounds, function(err, salt) {
            if(err)
                return next(err)
            bcrypt.hash(user.password, salt, function(err, hash) {
                // Store hash in your password DB.
                if(err)
                    next(err)
                user.password = hash
                next()
            });
        });
    } else { // 비밀번호 변경하지 않으면
        next();
    }
})

userSchema.methods.comparePassword = function(plainPassword, cb) {
    // plainPassword 1234567 => hasedPassword $2b$103vl...
    // hashed를 복호화는 불가능. plain을 암호화해서 비교해야 함.
    bcrypt.compare(plainPassword, this.password, function(err, isMatch) {
        if(err)
            return cb(err) // 아아아 여기 콤마 아니잖아요...!
        cb(null, isMatch)
    })
}

userSchema.methods.generateToken = function(cb) {
    var user = this;

    // jsonwebtoken을 이용해서 token 생성하기
    // user id로 token 생성
    // token 알면 user id 알 수 있다
    var token = jwt.sign(user._id.toHexString(), 'secretToken')
    user.token = token;
    user.save(function(err, user) {
        if(err)
            return cb(err)
        cb(null, user)
    })
}

userSchema.statics.findByToken = function(token, cb) {
    var user = this;

    // user._id + '' = token;
    // token decode
    jwt.verify(token, 'secretToken', function(err, decoded) {
        // user id로 user 찾기
        // 클라이언트의 token과 DB의 token이 일치하는지 확인

        user.findOne({ "_id": decoded, "token": token }, function(err, user) {
            if(err) return cb(err);
            cb(null, user)
        })
    })
}

const User = mongoose.model('User', userSchema)

module.exports = {User}