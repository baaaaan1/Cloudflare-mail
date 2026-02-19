const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const readline = require('readline');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

const question = (query) => new Promise((resolve) => rl.question(query, resolve));

async function main() {
  console.log('\x1b[36m%s\x1b[0m', '=== Cloudflare Email Panel AIO Setup ===');

  // 1. Install Dependencies
  console.log('\n\x1b[33m[1/5] Installing dependencies...\x1b[0m');
  try {
    console.log('  > Installing root packages...');
    execSync('npm install', { stdio: 'inherit' });
    
    console.log('  > Installing worker packages...');
    const workerDir = path.join(__dirname, 'worker');
    if (fs.existsSync(workerDir)) {
        execSync('npm install', { cwd: workerDir, stdio: 'inherit' });
    } else {
        console.error('  ! Worker directory not found.');
    }
  } catch (e) {
    console.error('\x1b[31mError installing dependencies:\x1b[0m', e.message);
    process.exit(1);
  }

  // 2. Setup .env
  console.log('\n\x1b[33m[2/5] Configuring Environment (.env)...\x1b[0m');
  const envPath = path.join(__dirname, '.env');
  let envContent = '';
  
  if (fs.existsSync(envPath)) {
    console.log('  .env file already exists.');
    envContent = fs.readFileSync(envPath, 'utf8');
  } else {
    console.log('  Creating .env file...');
    envContent = `CF_API_TOKEN=
CF_ACCOUNT_ID=
CF_ZONE_ID=
CF_D1_DATABASE_ID=
PORT=3000
`;
    fs.writeFileSync(envPath, envContent);
    console.log('  .env created.');
  }

  // 2.1 Interactive Config
  if (!envContent.match(/CF_API_TOKEN=[a-zA-Z0-9]+/)) {
    const doConfig = await question('  ? Do you want to configure Cloudflare credentials now? (y/n) ');
    if (doConfig.toLowerCase() === 'y') {
      const token = await question('    Enter CF_API_TOKEN: ');
      const accId = await question('    Enter CF_ACCOUNT_ID: ');
      const zoneId = await question('    Enter CF_ZONE_ID: ');
      
      let newEnv = fs.readFileSync(envPath, 'utf8');
      if (token) newEnv = newEnv.replace(/CF_API_TOKEN=.*/, `CF_API_TOKEN=${token.trim()}`);
      if (accId) newEnv = newEnv.replace(/CF_ACCOUNT_ID=.*/, `CF_ACCOUNT_ID=${accId.trim()}`);
      if (zoneId) newEnv = newEnv.replace(/CF_ZONE_ID=.*/, `CF_ZONE_ID=${zoneId.trim()}`);
      fs.writeFileSync(envPath, newEnv);
      envContent = newEnv;
      console.log('  > Credentials saved to .env');
    }
  }

  // 3. Cloudflare Login Check
  console.log('\n\x1b[33m[3/5] Checking Cloudflare Login...\x1b[0m');
  try {
    execSync('npx wrangler whoami', { cwd: path.join(__dirname, 'worker'), stdio: 'ignore' });
    console.log('  > You are logged in to Wrangler.');
  } catch (e) {
    console.log('  > You are NOT logged in.');
    const answer = await question('  ? Do you want to login now? (y/n) ');
    if (answer.toLowerCase() === 'y') {
      try {
        execSync('npx wrangler login', { cwd: path.join(__dirname, 'worker'), stdio: 'inherit' });
      } catch (e) {
        console.log('  ! Login failed or cancelled.');
      }
    }
  }

  // 4. D1 Database Setup
  console.log('\n\x1b[33m[4/5] D1 Database Setup...\x1b[0m');
  const dbName = 'email-db';
  let dbId = '';
  
  // Check if ID is already in .env
  const envMatch = envContent.match(/CF_D1_DATABASE_ID=(.*)/);
  if (envMatch && envMatch[1] && envMatch[1].trim() && !envMatch[1].includes('REPLACE')) {
      dbId = envMatch[1].trim();
      console.log(`  > Found Database ID in .env: ${dbId}`);
  } else {
      const createDb = await question(`  ? Do you want to create/fetch D1 database '${dbName}'? (y/n) `);
      if (createDb.toLowerCase() === 'y') {
          try {
              console.log('  > Checking database list...');
              let output = execSync(`npx wrangler d1 list --json`, { cwd: path.join(__dirname, 'worker'), encoding: 'utf8' });
              
              try {
                  const list = JSON.parse(output);
                  const db = list.find(d => d.name === dbName);
                  if (db) {
                      dbId = db.uuid;
                      console.log(`  > Found existing database: ${dbId}`);
                  } else {
                      console.log('  > Creating new database...');
                      const createOutput = execSync(`npx wrangler d1 create ${dbName}`, { cwd: path.join(__dirname, 'worker'), encoding: 'utf8' });
                      const match = createOutput.match(/database_id\s*=\s*"([a-f0-9-]+)"/i) || createOutput.match(/id\s*:\s*([a-f0-9-]+)/i);
                      if (match) dbId = match[1];
                  }
              } catch (e) {
                  console.log('  ! Failed to parse wrangler output.');
              }

              if (dbId) {
                  console.log(`  > Database ID: ${dbId}`);
                  
                  // Update .env
                  let newEnv = fs.readFileSync(envPath, 'utf8');
                  if (newEnv.includes('CF_D1_DATABASE_ID=')) {
                      newEnv = newEnv.replace(/CF_D1_DATABASE_ID=.*/, `CF_D1_DATABASE_ID=${dbId}`);
                  } else {
                      newEnv += `\nCF_D1_DATABASE_ID=${dbId}`;
                  }
                  fs.writeFileSync(envPath, newEnv);
                  console.log('  > Updated .env');

                  // Update wrangler.toml
                  const tomlPath = path.join(__dirname, 'worker', 'wrangler.toml');
                  const tomlExamplePath = path.join(__dirname, 'worker', 'wrangler.toml.example');
                  if (!fs.existsSync(tomlPath) && fs.existsSync(tomlExamplePath)) {
                      fs.copyFileSync(tomlExamplePath, tomlPath);
                      console.log('  > Created worker/wrangler.toml from example');
                  }
                  if (fs.existsSync(tomlPath)) {
                      let toml = fs.readFileSync(tomlPath, 'utf8');
                      toml = toml.replace(/database_id\s*=\s*".*"/, `database_id = "${dbId}"`);
                      fs.writeFileSync(tomlPath, toml);
                      console.log('  > Updated worker/wrangler.toml');
                  }
              } else {
                  console.log('  ! Could not auto-detect Database ID.');
              }
          } catch (e) {
              console.error('  ! Error managing D1 database:', e.message);
          }
      }
  }

  // 5. Deploy Worker
  console.log('\n\x1b[33m[5/5] Deploying Worker...\x1b[0m');
  const deploy = await question('  ? Do you want to deploy the worker now? (y/n) ');
  if (deploy.toLowerCase() === 'y') {
      try {
          execSync('npx wrangler deploy', { cwd: path.join(__dirname, 'worker'), stdio: 'inherit' });
          console.log('  > Worker deployed successfully.');
      } catch (e) {
          console.error('  ! Worker deployment failed.');
      }
  }

  console.log('\n\x1b[32m=== Setup Complete ===\x1b[0m');
  console.log('To start the panel, run:');
  console.log('  npm start');
  
  console.log('\n\x1b[36m=== Final Cloudflare Configuration ===\x1b[0m');
  console.log('1. \x1b[1mEnable Email Routing\x1b[0m: Go to Cloudflare Dashboard > Email > Email Routing and click "Get Started" to add DNS records.');
  console.log('2. \x1b[1mConnect Worker\x1b[0m: Once the panel is running, create a rule to "Send to Worker" and use the name: \x1b[33minbox-worker\x1b[0m');
  
  rl.close();
}

main();
