const Sequelize = require('sequelize');

const sequelize = new Sequelize ({
  dialect: 'sqlite',
  storage: 'fsjstd-restapi.db',
  logging: false,
});

(async () => {
  try {
	  await sequelize.authenticate();
	  console.log('Nailed it! The database is connected.');
  } catch (error) {
  	console.error('Oh no! Database connection error: ', error);
  }	
})();
 
const db = {
  sequelize,
  Sequelize,
  models: {},
};

db.models.Course = require('./models/Course.js')(sequelize);
db.models.User = require('./models/User.js')(sequelize);

module.exports = db;