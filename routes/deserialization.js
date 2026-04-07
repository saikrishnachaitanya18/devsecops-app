// INSECURE DESERIALIZATION ROUTES
// VULNERABILITIES: node-serialize RCE, unsafe JSON parsing, YAML deserialization

const express = require('express');
const router = express.Router();
const serialize = require('node-serialize');
const yaml = require('js-yaml');
const _ = require('lodash');

// ----------------------------------------------------------------
// VULNERABILITY: Insecure deserialization with node-serialize
// ----------------------------------------------------------------
router.get('/', (req, res) => {
  res.render('deserialization', {
    output: null,
    error: null,
    user: req.session.user || null,
    yamlOutput: null,
    yamlError: null,
    mergeOutput: null,
    mergeError: null
  });
});

router.post('/deserialize', (req, res) => {
  const { data } = req.body;

  try {
    // VULN: Insecure deserialization — can lead to RCE
    const obj = serialize.unserialize(data);
    res.render('deserialization', {
      output: JSON.stringify(obj, null, 2),
      error: null,
      user: req.session.user || null,
      yamlOutput: null,
      yamlError: null,
      mergeOutput: null,
      mergeError: null
    });
  } catch (err) {
    res.render('deserialization', {
      output: null,
      error: err.message,
      user: req.session.user || null,
      yamlOutput: null,
      yamlError: null,
      mergeOutput: null,
      mergeError: null
    });
  }
});

// ----------------------------------------------------------------
// VULNERABILITY: Unsafe YAML parsing (allows code execution)
// ----------------------------------------------------------------
router.post('/yaml', (req, res) => {
  const { yamlData } = req.body;

  try {
    // VULN: yaml.load without safe schema allows arbitrary JS execution
    const result = yaml.load(yamlData);
    res.render('deserialization', {
      output: null,
      error: null,
      user: req.session.user || null,
      yamlOutput: JSON.stringify(result, null, 2),
      yamlError: null,
      mergeOutput: null,
      mergeError: null
    });
  } catch (err) {
    res.render('deserialization', {
      output: null,
      error: null,
      user: req.session.user || null,
      yamlOutput: null,
      yamlError: err.message,
      mergeOutput: null,
      mergeError: null
    });
  }
});

// ----------------------------------------------------------------
// VULNERABILITY: Prototype Pollution via lodash merge
// ----------------------------------------------------------------
router.post('/merge', (req, res) => {
  const { target, source } = req.body;

  try {
    const targetObj = JSON.parse(target || '{}');
    const sourceObj = JSON.parse(source || '{}');

    // VULN: Prototype pollution — merging user-controlled objects
    const result = _.merge(targetObj, sourceObj);

    res.render('deserialization', {
      output: null,
      error: null,
      user: req.session.user || null,
      yamlOutput: null,
      yamlError: null,
      mergeOutput: JSON.stringify(result, null, 2),
      mergeError: null
    });
  } catch (err) {
    res.render('deserialization', {
      output: null,
      error: null,
      user: req.session.user || null,
      yamlOutput: null,
      yamlError: null,
      mergeOutput: null,
      mergeError: err.message
    });
  }
});

// ----------------------------------------------------------------
// VULNERABILITY: Unsafe JSON.parse with Function constructor
// ----------------------------------------------------------------
router.post('/execute', (req, res) => {
  const { funcBody } = req.body;

  try {
    // VULN: Creating and executing function from user input
    const fn = new Function(funcBody);
    const result = fn();
    res.json({ result: String(result) });
  } catch (err) {
    res.json({ error: err.message });
  }
});

module.exports = router;
