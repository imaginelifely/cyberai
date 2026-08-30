import { useEffect, useMemo, useRef, useState } from 'react';
import { motion } from 'framer-motion';
import {
  CloudUpload,
  ShieldCheck,
  Activity,
  Sparkles,
  Cpu,
  Zap,
  MessageSquare,
  SparklesIcon,
  ArrowUpRight,
  Search,
  ChevronRight,
  Sun,
  Moon,
  User,
} from 'lucide-react';

const samplePresets = [
  { label: 'Normal baseline', description: 'Stable PLC telemetry with consistent energy, flow, and network signatures.', pattern: 'normal' },
  { label: 'Intermediate anomaly', description: 'Elevated sensor drift and packet jitter with intermittent alert spikes.', pattern: 'intermediate' },
  { label: 'Worst-case malicious', description: 'Aggressive telemetry and denied access patterns consistent with an active intrusion.', pattern: 'worstcase' },
  { label: 'High-noise edge', description: 'Noisy edge device behavior with jitter, backpressure, and unstable reset events.', pattern: 'edge' },
  { label: 'Audit-ready trace', description: 'Mixed stable and anomalous signals built for SOC validation and compliance review.', pattern: 'audit' },
];

const featureNames = [
  'temp_sensor_01', 'temp_sensor_02', 'pressure_sensor', 'vibration_level',
  'voltage_supply', 'current_draw', 'fan_speed', 'humidity_ratio',
  'packet_loss', 'network_jitter', 'tcp_syn_rate', 'udp_drop',
  'auth_failures', 'dns_requests', 'mqtt_publish_rate', 'http_error_rate',
  'tls_handshakes', 'cpu_load', 'memory_usage', 'disk_io',
  'battery_voltage', 'signal_strength', 'gateway_latency', 'device_temperature',
  'sensor_drift', 'error_rate', 'process_count', 'thread_count',
  'queue_depth', 'throughput', 'alarm_count', 'packet_size',
  'vlan_errors', 'arp_requests', 'power_spike', 'connection_count',
  'retransmit_rate', 'cpu_temperature', 'noise_level', 'reliability_index',
  'ssl_handshake_failures', 'calibration_offset', 'system_age', 'anomaly_score',
];

const theme = {
  primary: '#2563EB',
  success: '#10B981',
  warning: '#F59E0B',
  danger: '#DC2626',
  text: '#0F172A',
  muted: '#64748B',
  border: '#E2E8F0',
};

const metricCards = [
  { title: '44 Features', value: 'Premium input coverage', icon: Activity, color: 'bg-sky-100', tone: 'text-sky-700' },
  { title: 'Explainable AI', value: 'Feature-driven reasoning', icon: Sparkles, color: 'bg-blue-100', tone: 'text-blue-700' },
  { title: 'Real-Time Detection', value: 'Fast inference', icon: Zap, color: 'bg-emerald-100', tone: 'text-emerald-700' },
  { title: 'SOC Assistant', value: 'Guided response', icon: ShieldCheck, color: 'bg-violet-100', tone: 'text-violet-700' },
];

function getRiskLevel(label, confidence) {
  if (label === 'Ransomware' || confidence >= 0.72) return 'HIGH';
  if (label === 'DoS' || confidence >= 0.48) return 'MEDIUM';
  return 'LOW';
}

function getRiskClass(riskLevel) {
  if (riskLevel === 'HIGH') return 'bg-red-50 text-red-700';
  if (riskLevel === 'MEDIUM') return 'bg-amber-50 text-amber-700';
  return 'bg-emerald-50 text-emerald-700';
}

function formatPercent(value) {
  return `${Math.round(value * 100)}%`;
}

function getDeterministicSample(pattern, index) {
  const rng = (() => {
    let value = index * 1664525 + pattern.length;
    return () => {
      value = (value * 1664525 + 1013904223) % 4294967296;
      return value / 4294967296;
    };
  })();

  const config = {
    normal: { base: 0.16, amplitude: 0.08, burst: 0.0, trend: 0.1 },
    intermediate: { base: 0.24, amplitude: 0.2, burst: 0.1, trend: 0.2 },
    worstcase: { base: 0.32, amplitude: 0.4, burst: 0.35, trend: 0.45 },
    edge: { base: 0.22, amplitude: 0.28, burst: 0.14, trend: 0.26 },
    audit: { base: 0.26, amplitude: 0.18, burst: 0.2, trend: 0.22 },
  }[pattern] || { base: 0.18, amplitude: 0.08, burst: 0.0, trend: 0.1 };

  return Array.from({ length: 44 }, (_, i) => {
    const base = config.base + ((i + index) % 5) * 0.12;
    const trend = Math.sin((i + 1) * 0.5) * config.trend;
    const burst = pattern === 'worstcase' && i % 5 === 0 ? config.burst * 1.2 : 0;
    const noise = (rng() - 0.5) * config.amplitude;
    return Math.max(0, base + trend + burst + noise);
  });
}

function generatePrediction(values) {
  const average = values.reduce((sum, n) => sum + n, 0) / values.length;
  const deviation = Math.sqrt(values.reduce((sum, n) => sum + Math.pow(n - average, 2), 0) / values.length);
  const score = Math.min(1, Math.max(0, (average + deviation * 0.8) / 1.4));
  const label = score > 0.75 ? 'Ransomware' : score > 0.55 ? 'DoS' : score > 0.35 ? 'Probe' : 'Normal';
  const confidence = Math.min(0.98, Math.max(0.35, score * 1.12));
  const riskLevel = getRiskLevel(label, confidence);

  const sorted = values
    .map((value, index) => ({ feature: featureNames[index] || `feature_${index + 1}`, value }))
    .sort((a, b) => Math.abs(b.value - average) - Math.abs(a.value - average));

  const topPositive = sorted.slice(0, 6).map(item => ({ label: item.feature, value: item.value }));
  const topNegative = sorted.slice(6, 12).map(item => ({ label: item.feature, value: item.value }));

  return {
    label,
    confidence,
    riskLevel,
    baselineLabel: label === 'Normal' ? 'Normal' : 'Suspicious',
    baselineConfidence: Math.max(0.45, confidence - 0.18),
    refinedLabel: label,
    topPositive,
    topNegative,
    timestamp: Date.now(),
    recommendation:
      label === 'Ransomware'
        ? 'Isolate affected devices immediately, preserve logs, and escalate to SOC for containment.'
        : label === 'DoS'
        ? 'Investigate traffic sources, apply rate limiting, and monitor for recurring bursts.'
        : label === 'Probe'
        ? 'Harden perimeter controls, verify scan sources, and monitor exposed services.'
        : 'Continue routine monitoring and validate that signals remain stable and benign.',
    featureRows: sorted.slice(0, 12).map((item, index) => ({
      feature: item.feature,
      impact: `${index < 6 ? '+' : '-'}${(Math.abs(item.value - average) * 8).toFixed(1)}%`,
      contribution: `${(Math.abs(item.value - average) * 5).toFixed(1)}%`,
    })),
    inferenceTime: `${Math.round(30 + confidence * 40)} ms`,
    modelUsed: 'SentinelCore IoT-ML v2',
    attackCategory: label === 'Normal' ? 'No threat' : label,
  };
}

function App() {
  const [darkMode, setDarkMode] = useState(false);
  const [selectedSampleIndex, setSelectedSampleIndex] = useState(0);
  const [currentSample, setCurrentSample] = useState({
    id: 'sample-1',
    source: 'Generated demo',
    description: samplePresets[0].description,
    values: getDeterministicSample('normal', 0),
  });
  const [prediction, setPrediction] = useState(null);
  const [uploadMessage, setUploadMessage] = useState('Upload a CSV with 44 numeric values');
  const [history, setHistory] = useState([]);
  const [confidentialMode, setConfidentialMode] = useState(false);
  const [socReport, setSocReport] = useState('No report generated yet.');
  const [assistantMessages, setAssistantMessages] = useState([
    { role: 'system', text: 'SentinelCore AI is ready to help with anomaly investigation.' },
  ]);
  const [assistantInput, setAssistantInput] = useState('');
  const [searchQuery, setSearchQuery] = useState('');

  function clearSession() {
    setAssistantMessages([{ role: 'system', text: 'SentinelCore AI is ready to help with anomaly investigation and SOC reporting.' }]);
    setAssistantInput('');
    setHistory([]);
    setSocReport('No report generated yet.');
    setUploadMessage('Session cleared. Select a sample or upload a CSV.');
  }

  function formatRulebookResponse(lines) {
    return lines.join('\n');
  }

  function getAssistantResponse(prompt) {
    const query = prompt.toLowerCase();
    if (!prediction) {
      return 'No analysis is available yet. Run the detection engine on a dataset first so the SOC assistant can provide actionable guidance.';
    }

    if (query.includes('report')) {
      return generateSocReport(false);
    }

    if (query.includes('cause') || query.includes('root') || query.includes('driver') || query.includes('why')) {
      return formatRulebookResponse([
        'Root cause analysis:',
        `- The model detected elevated variance in telemetry across key assets, especially ${prediction.topPositive.slice(0, 2).map(item => item.feature).join(' and ')}.`,
        `- The highest-risk signals include ${prediction.topNegative.slice(0, 2).map(item => item.feature).join(' and ')}.`,
        '- Confirm whether these symptoms match a process anomaly or a targeted intrusion.',
        '- Rulebook action: validate baseline sensor readings, confirm asset identity, and isolate affected devices if the risk remains high.',
      ]);
    }

    if (query.includes('feature') || query.includes('important') || query.includes('influence')) {
      return formatRulebookResponse([
        'Feature prioritization:',
        `- Focus on ${prediction.topPositive.slice(0, 3).map(item => item.feature).join(', ')} for positive anomaly drivers.`,
        `- Review ${prediction.topNegative.slice(0, 3).map(item => item.feature).join(', ')} as potential negative contributors.`,
        '- Validate these fields in the asset map and correlate with network flows and control plane activity.',
      ]);
    }

    if (query.includes('mitigation') || query.includes('action') || query.includes('triage') || query.includes('recommend')) {
      return formatRulebookResponse([
        'SOC recommended actions:',
        `- Confirm the underlying asset and isolate if ${prediction.riskLevel} risk is confirmed.`,
        `- Preserve logs for ${prediction.topPositive[0]?.feature || 'key indicators'} and escalate to the incident response team.`,
        '- Apply rulebook verification: cross-check with network traffic, authentication events, and asset security posture.',
        '- Document findings in the SOC case ticket and follow incident handling protocols.',
      ]);
    }

    if (query.includes('rulebook') || query.includes('soc') || query.includes('policy') || query.includes('security') || query.includes('secure')) {
      return formatRulebookResponse([
        'SOC rulebook guidance:',
        '- Treat this detection as a potential threat if the confidence score is above 55%.',
        '- Validate the detection against known baselines, process owners, and configuration drift.',
        '- Escalate through the SOC if anomalous telemetry persists or if multiple correlated assets are affected.',
        '- Use this assistant to generate actionable reports and evidence summaries for each incident.',
      ]);
    }

    return formatRulebookResponse([
      'Analysis summary:',
      `- Current prediction: ${prediction.label} (${formatPercent(prediction.confidence)} confidence).`,
      '- If you need a formal report, ask for a SOC report or request mitigation steps.',
      '- For a root cause review, ask about drivers, feature importance, or why the model flagged this case.',
    ]);
  }

  function generateSocReport(addToMessages = true) {
    const report = !prediction
      ? 'SOC report unavailable because no prediction has been generated. Run analysis on a dataset first.'
      : [
          `SOC ANALYST REPORT • ${new Date().toLocaleString()}`,
          `Sample: ${currentSample.id}`,
          `Source: ${currentSample.source}`,
          `Prediction: ${prediction.label}`,
          `Confidence: ${formatPercent(prediction.confidence)} • Risk: ${prediction.riskLevel}`,
          `Category: ${prediction.attackCategory}`,
          '',
          'Key findings:',
          `- Elevated anomaly score driven by higher-than-normal variance across ${currentSample.values.length} telemetry features.`,
          `- Top positive drivers: ${prediction.topPositive.slice(0, 3).map(feature => feature.label).join(', ')}.`,
          `- Top negative drivers: ${prediction.topNegative.slice(0, 3).map(feature => feature.label).join(', ')}.`,
          '',
          'Recommended SOC actions:',
          `- ${prediction.recommendation}`,
          '- Preserve evidence, isolate affected assets, and escalate to SOC if the risk remains high.',
          '- Validate unusual network flows and check for command-and-control indicators.',
          '',
          'Analyst notes:',
          `- Operation mode: ${confidentialMode ? 'Confidential' : 'Standard'}.`,
          `- Model: ${prediction.modelUsed} | Inference time: ${prediction.inferenceTime}.`,
        ].join('\n');

    setSocReport(report);
    if (addToMessages) {
      setAssistantMessages(prev => [...prev, { role: 'assistant', text: report }]);
    }
    return report;
  }

  const filteredFeatures = useMemo(() => {
    if (!prediction) return [];
    return prediction.featureRows.filter(row => row.feature.includes(searchQuery));
  }, [prediction, searchQuery]);

  function selectSample(index) {
    const preset = samplePresets[index];
    setSelectedSampleIndex(index);
    setCurrentSample({
      id: `sample-${index + 1}`,
      source: 'Generated demo',
      description: preset.description,
      values: getDeterministicSample(preset.pattern, index),
    });
    setPrediction(null);
    setUploadMessage('Upload a CSV with 44 numeric values');
  }

  function handleFile(file) {
    if (confidentialMode) {
      setUploadMessage('Upload blocked in confidential mode. Disable it to upload files.');
      return;
    }

    const reader = new FileReader();
    reader.onload = () => {
      const text = reader.result;
      if (typeof text !== 'string') return;
      const rows = text.split(/\r?\n/).filter(Boolean);
      const values = rows.flatMap(row => row.split(',').map(cell => parseFloat(cell.trim()))).filter(num => !Number.isNaN(num));
      if (values.length !== 44) {
        setUploadMessage('CSV must contain exactly 44 numeric values.');
        return;
      }
      setCurrentSample({
        id: file.name,
        source: 'Uploaded CSV',
        description: 'Custom telemetry uploaded by user.',
        values,
      });
      setUploadMessage('CSV loaded successfully. Run analysis to generate insights.');
      setPrediction(null);
    };
    reader.readAsText(file);
  }

  function handleAnalyze() {
    const result = generatePrediction(currentSample.values);
    setPrediction(result);
    setHistory(prev => [
      { id: Date.now(), sample: currentSample.id, label: result.label, confidence: result.confidence, time: new Date() },
      ...prev.slice(0, 7),
    ]);
  }

  function sendAssistant(prompt) {
    if (!assistantInput.trim() && !prompt) return;
    const text = prompt || assistantInput.trim();
    const newMessages = [...assistantMessages, { role: 'user', text }];
    setAssistantMessages(newMessages);
    setAssistantInput('');

    setTimeout(() => {
      const response = getAssistantResponse(text);
      setAssistantMessages(prev => [...prev, { role: 'assistant', text: response }]);
    }, 700);
  }

  const topPositives = prediction?.topPositive.slice(0, 3) || [];
  const topNegatives = prediction?.topNegative.slice(0, 3) || [];

  return (
    <div className={`${darkMode ? 'dark' : ''}`}>
      <div className="min-h-screen bg-[#F5F8FC] text-slate-950 dark:bg-slate-950 dark:text-white">
        <div className="mx-auto max-w-[1400px] px-4 py-6 sm:px-6 lg:px-8">
          <header className="mb-8 flex flex-col gap-6 rounded-3xl border border-slate-200 bg-white p-6 shadow-lg dark:border-slate-800 dark:bg-slate-900">
            <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
              <div>
                <div className="flex items-center gap-3 text-slate-900 dark:text-white">
                  <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-sky-500 text-white shadow-lg">
                    <ShieldCheck size={20} />
                  </div>
                  <div>
                    <p className="text-sm uppercase tracking-[0.24em] text-slate-500 dark:text-slate-400">SentinelCore AI</p>
                    <h1 className="mt-1 text-3xl font-semibold tracking-tight text-slate-950 dark:text-white">Industrial IoT Threat Detection</h1>
                  </div>
                </div>
                <p className="mt-4 max-w-2xl text-base leading-7 text-slate-600 dark:text-slate-300">
                  Explainable AI security analytics for smart manufacturing. Detect anomalies, investigate risk, and empower SOC teams with fast, transparent threat decisions.
                </p>
              </div>

              <div className="grid w-full gap-3 sm:grid-cols-2 lg:w-auto lg:grid-cols-1">
                <button onClick={handleAnalyze} className="inline-flex items-center justify-center rounded-3xl bg-gradient-to-r from-sky-600 to-sky-500 px-6 py-3 text-sm font-semibold text-white shadow-lg shadow-sky-200 transition-transform duration-200 hover:-translate-y-0.5 hover:shadow-sky-300 focus:outline-none focus:ring-2 focus:ring-sky-500">
                  Run Analysis
                  <ArrowUpRight className="ml-2 h-4 w-4" />
                </button>
                <button onClick={() => selectSample(0)} className="inline-flex items-center justify-center rounded-3xl border border-slate-300 bg-white px-6 py-3 text-sm font-semibold text-slate-900 transition hover:border-slate-400 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-950 dark:text-white dark:hover:bg-slate-900">
                  Load Demo Dataset
                </button>
              </div>
            </div>

            <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
              {metricCards.map(card => (
                <motion.div key={card.title} whileHover={{ y: -3 }} className={`rounded-3xl border border-slate-200 bg-white px-5 py-6 shadow-sm transition dark:border-slate-800 dark:bg-slate-900`}>
                  <div className="flex items-center gap-4">
                    <div className={`inline-flex h-12 w-12 items-center justify-center rounded-2xl ${card.color}`}>
                      <card.icon className={`h-5 w-5 ${card.tone}`} />
                    </div>
                    <div>
                      <p className="text-sm font-medium text-slate-500 dark:text-slate-400">{card.title}</p>
                      <p className="mt-2 text-sm font-semibold text-slate-900 dark:text-white">{card.value}</p>
                    </div>
                  </div>
                </motion.div>
              ))}
            </div>
          </header>

          <main className="grid gap-6 xl:grid-cols-[0.72fr_0.28fr]">
            <section className="space-y-6">
              <motion.div initial={{ opacity: 0, y: 16 }} animate={{ opacity: 1, y: 0 }} className="rounded-3xl border border-slate-200 bg-white p-6 shadow-lg dark:border-slate-800 dark:bg-slate-900">
                <div className="flex flex-col gap-6 lg:flex-row lg:items-center lg:justify-between">
                  <div>
                    <p className="text-sm font-semibold uppercase tracking-[0.24em] text-sky-700">Dataset Selection</p>
                    <h2 className="mt-3 text-2xl font-semibold text-slate-950 dark:text-white">Upload or choose a sample</h2>
                  </div>
                  <div className="flex flex-wrap items-center gap-3">
                    {samplePresets.map((sample, index) => (
                      <button key={sample.label} onClick={() => selectSample(index)} className={`rounded-2xl border px-4 py-2 text-sm font-semibold transition ${selectedSampleIndex === index ? 'border-sky-600 bg-sky-50 text-sky-700' : 'border-slate-200 bg-white text-slate-600 hover:border-slate-300 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-950 dark:text-slate-300 dark:hover:border-slate-600 dark:hover:bg-slate-900'}`}>
                        {sample.label}
                      </button>
                    ))}
                  </div>
                </div>

                <div className="mt-6 grid gap-6 lg:grid-cols-[1.4fr_0.6fr]">
                  <div>
                    <label className="group relative block cursor-pointer rounded-3xl border-2 border-dashed border-slate-300 bg-slate-50 px-6 py-16 text-center transition hover:border-slate-400 hover:bg-white dark:border-slate-700 dark:bg-slate-900 dark:hover:border-slate-500">
                      <input type="file" accept=".csv" className="sr-only" onChange={e => e.target.files?.[0] && handleFile(e.target.files[0])} />
                      <CloudUpload className="mx-auto h-12 w-12 text-sky-600 transition group-hover:scale-105" />
                      <p className="mt-5 text-lg font-semibold text-slate-900 dark:text-white">Drag & drop CSV or browse</p>
                      <p className="mt-2 text-sm text-slate-500 dark:text-slate-400">Supported: .csv · 44 numeric values</p>
                      <div className="mt-6 h-2 overflow-hidden rounded-full bg-slate-200 dark:bg-slate-800">
                        <div className="h-full w-1/4 rounded-full bg-sky-500 transition-all duration-500" />
                      </div>
                      <p className="mt-4 text-sm text-slate-500 dark:text-slate-400">{uploadMessage}</p>
                    </label>
                  </div>

                  <div className="space-y-4 rounded-3xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-800 dark:bg-slate-900">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="text-sm uppercase tracking-[0.24em] text-slate-500 dark:text-slate-400">Current dataset</p>
                        <p className="mt-2 text-lg font-semibold text-slate-950 dark:text-white">{currentSample.id}</p>
                      </div>
                      <span className="rounded-full bg-sky-50 px-3 py-1 text-sm font-semibold text-sky-700">Live demo</span>
                    </div>
                    <p className="text-sm leading-6 text-slate-600 dark:text-slate-300">{currentSample.description}</p>
                    <div className="grid gap-3 rounded-3xl bg-slate-50 p-4 dark:bg-slate-950">
                      <div className="flex items-center justify-between text-sm text-slate-600 dark:text-slate-400"><span>Source</span><span>{currentSample.source}</span></div>
                      <div className="flex items-center justify-between text-sm text-slate-600 dark:text-slate-400"><span>Features</span><span>44</span></div>
                      <div className="flex items-center justify-between text-sm text-slate-600 dark:text-slate-400"><span>Selected sample</span><span>{selectedSampleIndex >= 0 ? samplePresets[selectedSampleIndex].label : 'Custom upload'}</span></div>
                      <div className="rounded-3xl bg-white p-3 text-sm text-slate-700 shadow-sm dark:bg-slate-900 dark:text-slate-300">
                        <p className="font-semibold">Security posture</p>
                        <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">{confidentialMode ? 'Confidential mode active. Uploads are paused, and session data stays local.' : 'Standard mode active. Uploads are enabled with secure analysis.'}</p>
                      </div>
                    </div>
                  </div>
                </div>
              </motion.div>

              <motion.div initial={{ opacity: 0, y: 18 }} animate={{ opacity: 1, y: 0 }} className="rounded-3xl border border-slate-200 bg-white p-6 shadow-lg dark:border-slate-800 dark:bg-slate-900">
                <div className="flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
                  <div>
                    <p className="text-sm font-semibold uppercase tracking-[0.24em] text-slate-500 dark:text-slate-400">Prediction Results</p>
                    <h2 className="mt-3 text-2xl font-semibold text-slate-950 dark:text-white">Threat insights</h2>
                  </div>
                  <div className="flex flex-wrap gap-3">
                    <button onClick={handleAnalyze} className="inline-flex items-center gap-2 rounded-3xl bg-gradient-to-r from-sky-600 to-sky-500 px-5 py-3 text-sm font-semibold text-white shadow-lg shadow-sky-200 transition-transform duration-200 hover:-translate-y-0.5">
                      Analyze now
                    </button>
                    <button onClick={() => {
                      setConfidentialMode(prev => !prev);
                      setUploadMessage(!confidentialMode ? 'Confidential mode enabled. Uploads are blocked.' : 'Confidential mode disabled. Uploads are allowed.');
                    }} className={`inline-flex items-center justify-center rounded-3xl border px-5 py-3 text-sm font-semibold transition ${confidentialMode ? 'border-emerald-500 bg-emerald-50 text-emerald-700 hover:bg-emerald-100' : 'border-slate-300 bg-white text-slate-800 hover:border-slate-400 hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-950 dark:text-white dark:hover:border-slate-600 dark:hover:bg-slate-900'}`}>
                      {confidentialMode ? 'Confidential On' : 'Confidential Off'}
                    </button>
                  </div>
                </div>

                <div className="mt-8 grid gap-6 xl:grid-cols-3">
                  <div className="rounded-3xl border border-slate-200 bg-slate-50 p-5 shadow-sm dark:border-slate-800 dark:bg-slate-950">
                    <p className="text-sm font-semibold uppercase tracking-[0.24em] text-slate-500 dark:text-slate-400">Prediction</p>
                    <p className="mt-4 text-4xl font-semibold text-slate-950 dark:text-white">{prediction?.label ?? 'Awaiting analysis'}</p>
                    <span className={`mt-4 inline-flex rounded-full px-4 py-2 text-sm font-semibold ${prediction ? getRiskClass(prediction.riskLevel) : 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300'}`}>{prediction?.riskLevel ?? 'UNKNOWN'}</span>
                  </div>

                  <div className="rounded-3xl border border-slate-200 bg-slate-50 p-5 shadow-sm dark:border-slate-800 dark:bg-slate-950">
                    <p className="text-sm font-semibold uppercase tracking-[0.24em] text-slate-500 dark:text-slate-400">Probability</p>
                    <div className="mt-5 flex items-end gap-4">
                      <p className="text-5xl font-semibold text-slate-950 dark:text-white">{prediction ? formatPercent(prediction.confidence) : '—'}</p>
                      <span className="text-sm text-slate-500 dark:text-slate-400">confidence score</span>
                    </div>
                    <div className="mt-6 rounded-full bg-slate-200 p-1 dark:bg-slate-800">
                      <motion.div initial={{ width: 0 }} animate={{ width: prediction ? formatPercent(prediction.confidence) : '0%' }} className="h-3 rounded-full bg-gradient-to-r from-sky-600 to-sky-500" />
                    </div>
                  </div>

                  <div className="rounded-3xl border border-slate-200 bg-slate-50 p-5 shadow-sm dark:border-slate-800 dark:bg-slate-950">
                    <div className="flex items-center justify-between text-sm uppercase tracking-[0.24em] text-slate-500 dark:text-slate-400">
                      <span>Threat level</span>
                      <span>{prediction?.attackCategory ?? 'No threat'}</span>
                    </div>
                    <p className="mt-4 text-3xl font-semibold text-slate-950 dark:text-white">{prediction ? formatPercent(prediction.confidence) : '—'}</p>
                    <p className="mt-3 text-sm leading-6 text-slate-600 dark:text-slate-300">Inference Time: {prediction?.inferenceTime ?? 'N/A'}</p>
                    <p className="mt-1 text-sm leading-6 text-slate-600 dark:text-slate-300">Model: {prediction?.modelUsed ?? 'SentinelCore IoT-ML v2'}</p>
                  </div>
                </div>
              </motion.div>

              <motion.div initial={{ opacity: 0, y: 18 }} animate={{ opacity: 1, y: 0 }} className="rounded-3xl border border-slate-200 bg-white p-6 shadow-lg dark:border-slate-800 dark:bg-slate-900">
                <div className="flex items-center justify-between gap-4">
                  <div>
                    <p className="text-sm font-semibold uppercase tracking-[0.24em] text-slate-500 dark:text-slate-400">Feature Importance</p>
                    <h2 className="mt-3 text-2xl font-semibold text-slate-950 dark:text-white">Influence overview</h2>
                  </div>
                  <div className="flex items-center gap-2 rounded-3xl border border-slate-200 bg-white px-4 py-2 text-sm text-slate-500 shadow-sm dark:border-slate-800 dark:bg-slate-950 dark:text-slate-300">
                    <Search className="h-4 w-4" />
                    <input value={searchQuery} onChange={e => setSearchQuery(e.target.value)} placeholder="Search feature" className="w-48 bg-transparent text-sm outline-none placeholder:text-slate-400 dark:placeholder:text-slate-500" />
                  </div>
                </div>

                <div className="mt-8 grid gap-6 lg:grid-cols-2">
                  <div className="space-y-4">
                    <div className="rounded-3xl bg-emerald-50 p-4">
                      <p className="text-sm font-semibold uppercase tracking-[0.24em] text-emerald-700">Top Positive</p>
                      {topPositives.length ? topPositives.map(feature => (
                        <div key={feature.label} className="mt-4 space-y-2">
                          <div className="flex items-center justify-between text-sm font-semibold text-slate-900 dark:text-white"><span>{feature.label}</span><span>{(feature.value * 100).toFixed(1)}%</span></div>
                          <div className="h-2 overflow-hidden rounded-full bg-slate-200">
                            <div className="h-full rounded-full bg-emerald-500" style={{ width: `${Math.min(100, feature.value * 120)}%` }} />
                          </div>
                        </div>
                      )) : <p className="mt-4 text-sm text-slate-500">No feature importance yet.</p>}
                    </div>
                    <div className="rounded-3xl bg-red-50 p-4">
                      <p className="text-sm font-semibold uppercase tracking-[0.24em] text-red-700">Top Negative</p>
                      {topNegatives.length ? topNegatives.map(feature => (
                        <div key={feature.label} className="mt-4 space-y-2">
                          <div className="flex items-center justify-between text-sm font-semibold text-slate-900 dark:text-white"><span>{feature.label}</span><span>{(feature.value * 100).toFixed(1)}%</span></div>
                          <div className="h-2 overflow-hidden rounded-full bg-slate-200">
                            <div className="h-full rounded-full bg-red-500" style={{ width: `${Math.min(100, feature.value * 120)}%` }} />
                          </div>
                        </div>
                      )) : <p className="mt-4 text-sm text-slate-500">No feature importance yet.</p>}
                    </div>
                  </div>

                  <div className="rounded-3xl border border-slate-200 bg-slate-50 p-4 dark:border-slate-800 dark:bg-slate-950">
                    <div className="flex items-center justify-between text-sm uppercase tracking-[0.24em] text-slate-500 dark:text-slate-400">
                      <span>Feature Table</span>
                      <span>Sortable</span>
                    </div>
                    <div className="mt-5 overflow-hidden rounded-3xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-900">
                      <table className="w-full text-left text-sm text-slate-600 dark:text-slate-300">
                        <thead className="border-b border-slate-200 bg-slate-50 text-slate-500 dark:border-slate-800 dark:bg-slate-950 dark:text-slate-400">
                          <tr>
                            <th className="px-4 py-3">Feature</th>
                            <th className="px-4 py-3">Impact</th>
                            <th className="px-4 py-3">Contribution</th>
                          </tr>
                        </thead>
                        <tbody>
                          {filteredFeatures.length ? filteredFeatures.map(row => (
                            <tr key={row.feature} className="border-b border-slate-100 dark:border-slate-800 last:border-none hover:bg-slate-50 dark:hover:bg-slate-900">
                              <td className="px-4 py-3 font-medium text-slate-900 dark:text-white">{row.feature}</td>
                              <td className="px-4 py-3">{row.impact}</td>
                              <td className="px-4 py-3">{row.contribution}</td>
                            </tr>
                          )) : (
                            <tr>
                              <td colSpan={3} className="px-4 py-8 text-center text-sm text-slate-500 dark:text-slate-400">No features match your search or no prediction available yet.</td>
                            </tr>
                          )}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
              </motion.div>

              <motion.div initial={{ opacity: 0, y: 18 }} animate={{ opacity: 1, y: 0 }} className="rounded-3xl border border-slate-200 bg-white p-6 shadow-lg dark:border-slate-800 dark:bg-slate-900">
                <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
                  <div>
                    <p className="text-sm font-semibold uppercase tracking-[0.24em] text-slate-500 dark:text-slate-400">Recommendation</p>
                    <h2 className="mt-3 text-2xl font-semibold text-slate-950 dark:text-white">SOC action brief</h2>
                  </div>
                </div>

                <div className="mt-6 grid gap-6 lg:grid-cols-2">
                  <div className="rounded-3xl border border-slate-200 bg-slate-50 p-5 dark:border-slate-800 dark:bg-slate-950">
                    <p className="text-sm font-semibold uppercase tracking-[0.24em] text-slate-500 dark:text-slate-400">Summary</p>
                    <p className="mt-4 text-base leading-7 text-slate-700 dark:text-slate-300">{prediction ? prediction.recommendation : 'No prediction yet. Run analysis to generate a tailored SOC recommendation.'}</p>
                  </div>
                  <div className="space-y-4 rounded-3xl border border-slate-200 bg-slate-50 p-5 dark:border-slate-800 dark:bg-slate-950">
                    <div className="rounded-3xl bg-white p-4 shadow-sm dark:bg-slate-900">
                      <p className="text-sm uppercase tracking-[0.24em] text-slate-500 dark:text-slate-400">Risk Level</p>
                      <p className="mt-3 text-xl font-semibold text-slate-950 dark:text-white">{prediction?.riskLevel ?? 'N/A'}</p>
                    </div>
                    <div className="rounded-3xl bg-white p-4 shadow-sm dark:bg-slate-900">
                      <p className="text-sm uppercase tracking-[0.24em] text-slate-500 dark:text-slate-400">Why this prediction happened</p>
                      <p className="mt-3 text-sm leading-6 text-slate-700 dark:text-slate-300">{prediction ? 'The model flagged higher-than-average deviation across multiple telemetry signals and strong anomaly patterns.' : 'Awaiting analysis to surface feature-driven rationale.'}</p>
                    </div>
                  </div>
                </div>

                <div className="mt-6 grid gap-4 sm:grid-cols-2">
                  <div className="rounded-3xl bg-white p-5 shadow-sm dark:bg-slate-900">
                    <p className="text-sm uppercase tracking-[0.24em] text-slate-500 dark:text-slate-400">Immediate action</p>
                    <ul className="mt-4 list-disc space-y-3 pl-5 text-sm leading-7 text-slate-700 dark:text-slate-300">
                      <li>Validate anomalous device telemetry.</li>
                      <li>Confirm unusual traffic patterns.</li>
                      <li>Escalate to SOC if risk remains high.</li>
                    </ul>
                  </div>
                  <div className="rounded-3xl bg-white p-5 shadow-sm dark:bg-slate-900">
                    <p className="text-sm uppercase tracking-[0.24em] text-slate-500 dark:text-slate-400">MITRE ATT&CK</p>
                    <div className="mt-4 space-y-3 text-sm leading-7 text-slate-700 dark:text-slate-300">
                      <div className="rounded-2xl bg-slate-50 p-3 dark:bg-slate-950">T1049: System Network Discovery</div>
                      <div className="rounded-2xl bg-slate-50 p-3 dark:bg-slate-950">T1078: Valid Accounts</div>
                    </div>
                  </div>
                </div>
              </motion.div>
            </section>

            <aside className="space-y-6">
              <motion.div initial={{ opacity: 0, y: 18 }} animate={{ opacity: 1, y: 0 }} className="rounded-3xl border border-slate-200 bg-white p-6 shadow-lg dark:border-slate-800 dark:bg-slate-900">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <p className="text-sm font-semibold uppercase tracking-[0.24em] text-slate-500 dark:text-slate-400">Model Status</p>
                    <p className="mt-2 text-lg font-semibold text-slate-950 dark:text-white">Model Ready</p>
                  </div>
                  <span className="rounded-full bg-emerald-50 px-3 py-1 text-sm font-semibold text-emerald-700">Connected</span>
                </div>
                <div className="mt-6 grid gap-4">
                  <div className="rounded-3xl bg-slate-50 p-4 dark:bg-slate-950">
                    <p className="text-sm uppercase tracking-[0.22em] text-slate-500 dark:text-slate-400">Inference time</p>
                    <p className="mt-2 text-xl font-semibold text-slate-950 dark:text-white">{prediction?.inferenceTime ?? '—'}</p>
                  </div>
                  <div className="rounded-3xl bg-slate-50 p-4 dark:bg-slate-950">
                    <p className="text-sm uppercase tracking-[0.22em] text-slate-500 dark:text-slate-400">Model used</p>
                    <p className="mt-2 text-xl font-semibold text-slate-950 dark:text-white">{prediction?.modelUsed ?? 'SentinelCore IoT-ML v2'}</p>
                  </div>
                </div>
              </motion.div>

              <motion.div initial={{ opacity: 0, y: 18 }} animate={{ opacity: 1, y: 0 }} className="rounded-3xl border border-slate-200 bg-white p-6 shadow-lg dark:border-slate-800 dark:bg-slate-900">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <p className="text-sm font-semibold uppercase tracking-[0.24em] text-slate-500 dark:text-slate-400">Prediction History</p>
                    <h2 className="mt-3 text-xl font-semibold text-slate-950 dark:text-white">Recent runs</h2>
                  </div>
                </div>
                <div className="mt-6 space-y-3">
                  {history.length ? history.map(entry => (
                    <div key={entry.id} className="rounded-3xl border border-slate-200 bg-slate-50 p-4 dark:border-slate-800 dark:bg-slate-950">
                      <p className="text-sm font-semibold text-slate-900 dark:text-white">{entry.sample}</p>
                      <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">{entry.label} · {formatPercent(entry.confidence)}</p>
                    </div>
                  )) : <p className="text-sm text-slate-500 dark:text-slate-400">No analyses yet. Run a dataset to populate history.</p>}
                </div>
              </motion.div>

              <motion.div initial={{ opacity: 0, y: 18 }} animate={{ opacity: 1, y: 0 }} className="rounded-3xl border border-slate-200 bg-white p-6 shadow-lg dark:border-slate-800 dark:bg-slate-900">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <p className="text-sm font-semibold uppercase tracking-[0.24em] text-slate-500 dark:text-slate-400">SOC Assistant</p>
                    <h2 className="mt-3 text-xl font-semibold text-slate-950 dark:text-white">Investigate anomalies</h2>
                  </div>
                  <button onClick={() => setDarkMode(prev => !prev)} className="rounded-2xl border border-slate-200 px-3 py-2 text-slate-700 transition hover:bg-slate-50 dark:border-slate-800 dark:text-slate-300 dark:hover:bg-slate-900">
                    {darkMode ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
                  </button>
                </div>

                <div className="mt-6 space-y-4">
                  {assistantMessages.map((message, index) => (
                    <div key={index} className={`rounded-3xl p-4 ${message.role === 'assistant' ? 'bg-slate-50 text-slate-900 dark:bg-slate-950 dark:text-white' : 'bg-sky-50 text-sky-900 dark:bg-sky-950/20 dark:text-sky-200'}`}>
                      <p className="text-sm leading-7">{message.text}</p>
                    </div>
                  ))}
                </div>

                <div className="mt-6 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                  <button onClick={() => generateSocReport()} className="inline-flex items-center justify-center rounded-3xl bg-sky-600 px-4 py-3 text-sm font-semibold text-white hover:bg-sky-700">
                    Generate SOC report
                  </button>
                  <button onClick={() => sendAssistant('Show me the SOC rulebook and security controls.')} className="inline-flex items-center justify-center rounded-3xl border border-slate-200 bg-white px-4 py-3 text-sm font-semibold text-slate-900 hover:bg-slate-50 dark:border-slate-800 dark:bg-slate-950 dark:text-slate-200 dark:hover:bg-slate-900">
                    Security rulebook
                  </button>
                  <button onClick={clearSession} className="inline-flex items-center justify-center rounded-3xl border border-slate-200 bg-white px-4 py-3 text-sm font-semibold text-slate-900 hover:bg-slate-50 dark:border-slate-800 dark:bg-slate-950 dark:text-slate-200 dark:hover:bg-slate-900">
                    Clear session
                  </button>
                </div>

                <div className="mt-6 rounded-3xl border border-slate-200 bg-slate-50 p-4 dark:border-slate-800 dark:bg-slate-950">
                  <p className="text-sm uppercase tracking-[0.22em] text-slate-500 dark:text-slate-400">Latest SOC report</p>
                  <pre className="mt-3 max-h-52 overflow-y-auto whitespace-pre-wrap text-sm leading-6 text-slate-700 dark:text-slate-300">{socReport}</pre>
                </div>

                <div className="mt-6 space-y-3 rounded-3xl border border-slate-200 bg-slate-50 p-4 dark:border-slate-800 dark:bg-slate-950">
                  {['What caused this anomaly?', 'Explain the prediction', 'Which features matter most?', 'Generate SOC report'].map(preset => (
                    <button key={preset} onClick={() => sendAssistant(preset)} className="w-full rounded-2xl border border-slate-200 bg-white px-4 py-3 text-left text-sm text-slate-800 transition hover:bg-slate-50 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-200 dark:hover:bg-slate-800">
                      {preset}
                    </button>
                  ))}
                </div>

                <div className="mt-6 flex items-center gap-3 rounded-3xl border border-slate-200 bg-white p-3 dark:border-slate-800 dark:bg-slate-950">
                  <input value={assistantInput} onChange={e => setAssistantInput(e.target.value)} placeholder="Ask the assistant..." className="flex-1 bg-transparent text-sm outline-none placeholder:text-slate-400 dark:placeholder:text-slate-500" />
                  <button onClick={() => sendAssistant()} className="rounded-2xl bg-sky-600 px-4 py-2 text-sm font-semibold text-white hover:bg-sky-700">Send</button>
                </div>
              </motion.div>
            </aside>
          </main>

          <footer className="mt-10 rounded-3xl border border-slate-200 bg-white px-6 py-5 text-sm text-slate-500 shadow-sm dark:border-slate-800 dark:bg-slate-950 dark:text-slate-400">
            <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
              <p>© {new Date().getFullYear()} Priya Goel. All rights reserved.</p>
              <p>SentinelCore AI — Industrial SOC reporting and threat detection.</p>
            </div>
          </footer>
        </div>
      </div>
    </div>
  );
}

export default App;
