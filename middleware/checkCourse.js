// Require validator
const { check } = require('express-validator');

const checkCourse = [
    check('title')
        .exists({ checkNull: true, checkFalsy: true })
        .withMessage('Please provide title'),
    check('description')
        .exists({ checkNull: true, checkFalsy: true })
        .withMessage('Please provide a description'),
];

module.exports = checkCourse;
