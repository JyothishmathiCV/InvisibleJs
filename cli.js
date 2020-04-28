const {program} = require('commander');
const {eject,inject} = require('./invisible.js');
const CFonts = require('cfonts');
const color = require('colors');
const clipboardy = require('clipboardy');


var Spinner = require('./cli-spinner/index.js').Spinner;


function drawIntro(){
    CFonts.say('stegcloak', {
        font: 'block',
        align: 'center',
        colors: false,
        background: 'transparent',
        letterSpacing: 1,
        maxLength: '0',
        gradient: ['red', 'green'],
        independentGradient: false,
        transitionGradient: false,
        env: 'node'
      });
}



program
  .command('hide <secret> <password>')
  .option('-c, --cover <covertext>')
  .option('-i, --integrity')
  .action((secret,password, args) => {
      drawIntro();
      let cover = (args.cover)?args.cover:"This is a confidential text.";
      let payload=inject(secret,password,cover,args.integrity);
      clipboardy.writeSync(payload);
      console.log('Copied to clipboard'.grey);
});

program
  .command('reveal <password>')
  .option('-cp, --clip')
  .option('-d, --data <data>')
  .action((password,args) => {
      drawIntro();
      if(args.clip){payload=clipboardy.readSync();}
      else if(args.data){payload=args.data}
      else{console.log("Missing Data!"); return}
      let secret = eject(payload,password);
      console.log("Secret:".blue,secret.green);
  });

program.parse(process.argv);