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

    if(user.isModified('password')) { // ��й�ȣ �����
        // ��й�ȣ ��ȣȭ
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
    } else { // ��й�ȣ �������� ������
        next();
    }
})

userSchema.methods.comparePassword = function(plainPassword, cb) {
    // plainPassword 1234567 => hasedPassword $2b$103vl...
    // hashed�� ��ȣȭ�� �Ұ���. plain�� ��ȣȭ�ؼ� ���ؾ� ��.
    bcrypt.compare(plainPassword, this.password, function(err, isMatch) {
        if(err)
            return cb(err) // �ƾƾ� ���� �޸� �ƴ��ݾƿ�...!
        cb(null, isMatch)
    })
}

userSchema.methods.generateToken = function(cb) {
    var user = this;

    // jsonwebtoken�� �̿��ؼ� token �����ϱ�
    // user id�� token ����
    // token �˸� user id �� �� �ִ�
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
        // user id�� user ã��
        // Ŭ���̾�Ʈ�� token�� DB�� token�� ��ġ�ϴ��� Ȯ��

        user.findOne({ "_id": decoded, "token": token }, function(err, user) {
            if(err) return cb(err);
            cb(null, user)
        })
    })
}

const User = mongoose.model('User', userSchema)

module.exports = {User}