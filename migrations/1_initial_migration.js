/* global artifacts */
const Migrations = artifacts.require('Migrations')

module.exports = function(deployer) {
  if(deployer.network === 'movr') {
    return
  }
  deployer.deploy(Migrations)
}
