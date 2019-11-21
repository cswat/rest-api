'use strict';

const Sequelize = require('sequelize');

module.exports = (sequelize, DataTypes) => {
  const User = sequelize.define('User', {
    id: {
      type: Sequelize.INTEGER,
      primaryKey: true,
      autoIncrement: true
    },
    firstName: {
      type: Sequelize.STRING,
      allowNull: false
    },
    lastName: {
      type: Sequelize.STRING,
      allowNull: false
    },
    emailAddress: {
      type: Sequelize.STRING,
      allowNull: false
    },
    password: {
      type: Sequelize.STRING,
      allowNull: false
    },
  }, {});
  User.associate = function(models) {
    User.hasMany(models.Course, {
      foreignKey: {
        fieldName: 'userId',
        allowNull: false
      },
    });
  };
  return User;
};