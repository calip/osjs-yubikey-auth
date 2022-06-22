/*
 * OS.js - JavaScript Cloud/Web Desktop Platform
 *
 * Copyright (c) 2011-2020, Anders Evenrud <andersevenrud@gmail.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * @author  Anders Evenrud <andersevenrud@gmail.com>
 * @licence Simplified BSD License
 */
const bcrypt = require('bcrypt-nodejs');
const readline = require('readline');
const crypto = require('crypto');
const yub = require('yub');
const {EntitySchema, createConnection} = require('typeorm');

class User {
  constructor(id, username, password, otp_id, serial, name, groups, scenario_id, role_id) {
    this.id = id;
    this.username = username;
    this.password = password;
    this.otp_id = otp_id;
    this.serial = serial;
    this.name = name;
    this.groups = groups;
    this.scenario_id = scenario_id;
    this.role_id = role_id;
  }
}

const UserSchema = new EntitySchema({
  name: 'users',
  target: User,
  columns: {
    id: {
      primary: true,
      type: 'int',
      generated: true
    },
    username: {
      type: 'varchar'
    },
    password: {
      type: 'varchar'
    },
    otp_id: {
      type: 'varchar'
    },
    serial: {
      type: 'int'
    },
    name: {
      type: 'varchar',
      nullable: false
    },
    groups: {
      type: 'simple-array'
    },
    scenario_id: {
      type: 'int',
      nullable: false
    },
    role_id: {
      type: 'int',
      nullable: false
    }
  }
});

const encryptPassword = password => new Promise((resolve, reject) => {
  bcrypt.hash(password, null, null, (err, hash) => err ? reject(err) : resolve(hash));
});

const promptPassword = q => new Promise((resolve, reject) => {
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
  });

  rl.question(q, answer => {
    resolve(answer);
    rl.close();
  });

  rl._writeToOutput = s => rl.output.write('*');
});

const createPassword = () => promptPassword('Password: ')
  .then(pwd => encryptPassword(pwd));

const comparePassword = (password, hash) => new Promise((resolve, reject) => {
  bcrypt.compare(password, hash, (err, res) => resolve(res === true));
});

const createHash = otp => {
  return crypto.createHash('sha256').update(otp).digest('base64');
};

const validateOtp = (otp) => new Promise((resolve, reject) => {
  yub.verifyOffline(otp, (err, data) => {
    if(err) {
      reject(err);
    }
    data.valid = true;
    resolve(data);
  });
});

const createDb = (options) => {
  const settings = Object.assign({
    type: '',
    host: '',
    username: '',
    password: '',
    database: '',
    synchronize: true,
    entities: [UserSchema]
  }, options);

  return createConnection(settings);
};

module.exports = {
  User,
  createDb,
  createPassword,
  comparePassword,
  createHash,
  validateOtp
};
