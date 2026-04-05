const express = require('express');
const cors    = require('cors');
const fs      = require('fs');
const path    = require('path');

const app  = express();
const PORT = 3500;

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.text({ limit: '10mb' }));

const REPORTS_FILE = path.join(__dirname, 'reports.json');

if (!fs.existsSync(REPORTS_FILE)) {
  fs.writeFileSync(REPORTS_FILE, JSON.stringify({ reports: [], lastUpdate: null }));
}

function loadReports() {
  try { return JSON.parse(fs.readFileSync(REPORTS_FILE, 'utf8')); }
  catch(e) { return { reports: [], lastUpdate: null }; }
}

function saveReports(data) {
  fs.writeFileSync(REPORTS_FILE, JSON.stringify(data, null, 2));
}

// Jenkins envoie le rapport ici
app.post('/api/report', (req, res) => {
  const data = loadReports();

  const report = {
    id:        Date.now(),
    timestamp: new Date().toISOString(),
    tool:      req.body.tool      || 'Unknown',
    build:     req.body.build     || 'N/A',
    branch:    req.body.branch    || 'master',
    content:   req.body.content   || '',
    status:    req.body.status    || 'unknown'
  };

  data.reports.unshift(report);
  if (data.reports.length > 20) data.reports = data.reports.slice(0, 20);
  data.lastUpdate = report.timestamp;
  saveReports(data);

  console.log(`[${new Date().toLocaleTimeString()}] Rapport recu : ${report.tool} - Build ${report.build}`);
  res.json({ success: true, id: report.id });
});

// La page HTML recupere les rapports ici
app.get('/api/reports', (req, res) => {
  res.json(loadReports());
});

// Effacer tous les rapports
app.delete('/api/reports', (req, res) => {
  saveReports({ reports: [], lastUpdate: null });
  res.json({ success: true });
});

// Servir la page HTML directement
app.use(express.static(__dirname));

app.listen(PORT, () => {
  console.log(`
=== Security Dashboard Server ===
Serveur demarre sur http://localhost:${PORT}
En attente des rapports Jenkins...
`);
});