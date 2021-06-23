const { User } = require('../models/User');

let auth = (req, res, next) => {
    // ����ó���� �ϴ� ��

    // 1. Ŭ���̾�Ʈ ��Ű���� token ������
    let token = req.cookies.x_auth;

    // 2. token�� decode�ؼ� user ã��
    User.findByToken(token, (err, user) => {
        if(err) throw err;
        if(!user) return res.json({ isAuth: false, error: true })

        req.token = token;
        req.user = user;
        next();
    })

    // 3. user�� ������ ���� O

    // 4. user�� ������ ���� X
}

module.exports = {auth};