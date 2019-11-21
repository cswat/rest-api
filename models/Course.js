'use strict';

const Sequelize = require('sequelize');

module.exports = (sequelize, DataTypes) => {
  const Course = sequelize.define('Course', {
    id: {
      type: Sequelize.INTEGER,
      primaryKey: true,
      autoIncrement: true  
    },
    userId: {
      type: Sequelize.INTEGER,
      allowNull: false,
      foreignKey: true
    },
    title: {
      type: Sequelize.STRING,
    },
    description: {
      type: Sequelize.TEXT,
    },
    estimatedTime: {
      type: Sequelize.STRING,
      allowNull: true,
    },
    materialsNeeded: {
      type: Sequelize.STRING,
      allowNull: true,
    },
  }, {});
  Course.associate = function(models) {
    Course.belongsTo(models.User, {
      foreignKey: {
        fieldName: 'userId',
        allowNull: false,
      },
    });
  };
  return Course;
};