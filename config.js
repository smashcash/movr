require('dotenv').config()

module.exports = {
  deployments: {
    netId1285: {
      movr: {
        instanceAddress: {
          '0.1': '',
          '1': '',
          '10': '',
          '100': ''
        },
        symbol: 'MOVR',
        decimals: 18
      }
    }
    // ,
    // netId1287: {
    //   dev: {
    //     instanceAddress: {
    //       '0.1': '',
    //       '1': '',
    //       '100': '',
    //       '1000': ''
    //     },
    //     symbol: 'DEV',
    //     decimals: 18
    //   }
    // }
  }
}
