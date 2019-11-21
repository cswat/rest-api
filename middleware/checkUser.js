// Require validator
const { check } = require('express-validator');

const checkUser = [
    check('firstName')
        .exists({ checkNull: true, checkFalsy: true })
        .withMessage('Please provide a first name'),
    check('lastName')
        .exists({ checkNull: true, checkFalsy: true })
        .withMessage('Please provide a last name'),
    check('emailAddress')
        .isEmail()
        .withMessage('Please provide an email address'),
    check('password')
        .exists({ checkNull: true, checkFalsy: true })
        .withMessage('Please provide a password'),
];

module.exports = checkUser;
