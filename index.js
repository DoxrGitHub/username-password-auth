import express from 'express';
import { Client } from './client.js';
import path from "path";
import { fileURLToPath } from 'url';
import { dirname, resolve } from 'path';
import crypto from 'crypto';
import cookieParser from 'cookie-parser';
import ejs from "ejs";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const seed = process.env.seed || "defaultSeed"
const app = express();
let client = new Client('./database.json');
await client.set(null, null) // just make sure its initialized

app.use(express.json());
app.use(cookieParser());
app.use(express.static("pub"))
app.set("views", "priv");
app.set("view engine", "ejs");
app.engine('html', ejs.renderFile);

function makeid(length) {
  let result = '';
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789~!@#$%^&*()_-+=[{]}|";/?.>,<';
  const charactersLength = characters.length;
  let counter = 0;
  while (counter < length) {
    result += characters.charAt(Math.floor(Math.random() * charactersLength));
    counter += 1;
  }
  return result;
}

function ASCIImakeid(length) {
  let result = '';
  const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  const charactersLength = characters.length;
  let counter = 0;
  while (counter < length) {
    result += characters.charAt(Math.floor(Math.random() * charactersLength));
    counter += 1;
  }
  return result;
}

function dtm(days) {
  return days * 86400000
}

app.get("/", async (req, res) => {
  if (!req.cookies ||!req.cookies.auth) {
    // redirect to signup if no auth cookie is present
    res.redirect("/signup");
  } else {
    // find user data - search permitted cookies
    let userAccountData;
    for (const accountKey of await client.list("user-")) {
      const accountData = await client.get(accountKey);
      if (accountData && accountData.permittedCookies.includes(req.cookies.auth)) {
        userAccountData = accountData;
        break;
      }
    }

    if (userAccountData) {
      res.render('account.html', {
        username: userAccountData.username,
        SECRET_INFO: userAccountData.STABLE_ACCOUNT_SECRET
      });
    } else {
      res.status(403).send("Unauthorized access attempt.");
    }
  }
});

app.get("/signup", async (req, res) => {
  if (!req.cookies ||!req.cookies.auth) {
    res.sendFile(__dirname + "/pub/signup.html")
  } else {
    // find user data - search permitted cookies
    let userAccountData;
    for (const accountKey of await client.list("user-")) {
      const accountData = await client.get(accountKey);
      if (accountData && accountData.permittedCookies.includes(req.cookies.auth)) {
        userAccountData = accountData;
        break;
      }
    }

    if (userAccountData) {
      res.redirect("/")
    } else {
      res.status(403).send("Unauthorized access attempt.");
    }
  }
})

app.get("/login", async (req, res) => {
  if (!req.cookies ||!req.cookies.auth) {
    res.sendFile(__dirname + "/pub/login.html")
  } else {
    // find user data - search permitted cookies
    let userAccountData;
    for (const accountKey of await client.list("user-")) {
      const accountData = await client.get(accountKey);
      if (accountData && accountData.permittedCookies.includes(req.cookies.auth)) {
        userAccountData = accountData;
        break;
      }
    }

    if (userAccountData) {
      res.redirect("/")
    } else {
      res.status(403).send("Unauthorized access attempt.");
    }
  }
})

app.post("/login", async (req, res) => {
  const hash = crypto.createHash('sha256');
  let existVerityData = await client.get('user-' + req.body.username)
  if (existVerityData) {
        hash.update(req.body.username + req.body.password + seed);
        const digest = hash.digest('hex');
        // verify the user owns the account
        let userJson = await client.get("user-" + req.body.username)
        if (userJson.passHash === digest) {
      
        // create account cookie || the user is verified to be correct
        let newAuthCookie = makeid(500);

        res.cookie('auth', newAuthCookie, { maxAge: dtm(21), httpOnly: true });
      
        // add newAuthCookie to user's permittedCookies
          userJson.permittedCookies.push(newAuthCookie);
          await client.set("user-" + req.body.username, userJson)
          
          res.send("request went fine")
        } else {
          res.send("incorrect password") 
        }
    } else {
        res.send("user does not exist")
    }
})

app.post("/signup", async (req, res) => {
  let existVerityData = await client.get('user-' + req.body.username)
  const hash = crypto.createHash('sha256');
    if (!existVerityData) {
        hash.update(req.body.username + req.body.password + seed);

        let newAuthCookie = makeid(500);
      
        res.cookie('auth', newAuthCookie, { maxAge: dtm(21), httpOnly: true }); // for now we will just deal with expired cookies ig
        const digest = hash.digest('hex');
        await client.set("user-" + req.body.username, {
            username: req.body.username,
            passHash: digest,
            permittedCookies: [newAuthCookie],
            STABLE_ACCOUNT_SECRET: ASCIImakeid(200)
        });
        res.send("request went fine")
    } else {
        res.send("user already exists")
    }
})

app.listen(3000)