const { User } = require('../models/User');

let auth = (req, res, next) => {
    // 인증처리를 하는 곳

    // 1. 클라이언트 쿠키에서 token 가져옴
    let token = req.cookies.x_auth;

    // 2. token을 decode해서 user 찾기
    User.findByToken(token, (err, user) => {
        if(err) throw err;
        if(!user) return res.json({ isAuth: false, error: true })

        req.token = token;
        req.user = user;
        next();
    })

    // 3. user가 있으면 인증 O

    // 4. user가 없으면 인증 X
}

module.exports = {auth};