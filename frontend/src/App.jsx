import { useState } from 'react'
import './App.css'
const API_BASE_URL =
  import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000'

const modules = [
  { id: 'analyzer', name: 'Password Strength Analyzer', icon: '◈', description: 'Analyze password complexity, entropy and predictability.' },
  { id: 'dictionary', name: 'Dictionary Generator', icon: '▤', description: 'Generate wordlists using patterns and mutations.' },
  { id: 'simulator', name: 'Brute-Force Simulator', icon: '⚡', description: 'Calculate theoretical password search spaces in a controlled lab.' },
  { id: 'hashes', name: 'Hash Analyzer', icon: '#', description: 'Identify likely hash formats from authorized lab samples.' },
  { id: 'shadow', name: 'Linux Shadow Extractor', icon: '▥', description: 'Parse authorized offline Linux shadow-file samples and identify likely hash formats.' },
  { id: 'windows', name: 'Windows SAM/SYSTEM Analyzer', icon: '▦', description: 'Check supplied offline Windows registry-hive files.' },
  { id: 'reports', name: 'Security Audit Report', icon: '▧', description: 'Review findings, risks and mitigation recommendations.' },
]

const COMMON_WORDS = [
  'password', 'password123', '123456', 'qwerty', 'welcome',
  'admin', 'letmein', 'abc123', 'iloveyou', '111111',
]

const HASH_SAMPLES = [
  { name: 'MD5-shaped sample', value: '5f4dcc3b5aa765d61d8327deb882cf99' },
  { name: 'SHA-1-shaped sample', value: '356a192b7913b04c54574d18c28d46e6395428ab' },
  { name: 'SHA-256-shaped sample', value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' },
  { name: 'SHA-512 crypt-shaped sample', value: '$6$rounds=5000$salt$examplehashvalue' },
  { name: 'bcrypt-shaped sample', value: '$2b$12$abcdefghijklmnopqrstuu123456789012345678901234567890123' },
  { name: 'Argon2id-shaped sample', value: '$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$P2G6R7S8t9U0v1W2x3Y4z5A6B7C8d9E0f1G2h3I4j5k' },
]

function generateWordlist(words, years, options) {
  const results = new Set()
  const leetMap = { a: '@', e: '3', i: '1', o: '0', s: '$', t: '7' }

  function add(value) {
    if (value && value.length <= 128) results.add(value)
  }

  for (const original of words) {
    const word = original.trim()
    if (!word) continue
    add(word)

    if (options.caseVariants) {
      add(word.toLowerCase())
      add(word.toUpperCase())
      add(word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
    }

    if (options.leet) {
      let mutated = ''
      for (const char of word.toLowerCase()) mutated += leetMap[char] || char
      add(mutated)
    }

    if (options.numbers) {
      for (const number of ['1', '12', '123', '1234', '12345', '2025', '2026', ...years]) {
        add(`${word}${number}`)
        if (options.caseVariants) {
          add(`${word.charAt(0).toUpperCase()}${word.slice(1)}${number}`)
        }
      }
    }

    for (const year of years) {
      add(`${word}${year}`)
      add(`${word}@${year}`)
    }
  }

  return [...results]
}

function formatDuration(seconds) {
  if (!Number.isFinite(seconds)) return 'Extremely long'
  if (seconds < 1) return 'Less than 1 second'

  const units = [
    ['year', 365.25 * 24 * 60 * 60],
    ['day', 24 * 60 * 60],
    ['hour', 60 * 60],
    ['minute', 60],
    ['second', 1],
  ]

  for (const [name, size] of units) {
    if (seconds >= size) {
      const amount = seconds / size
      if (amount >= 1000) return `Approximately ${amount.toExponential(2)} ${name}s`
      return `Approximately ${amount.toLocaleString('en-US', { maximumFractionDigits: 2 })} ${name}${amount >= 2 ? 's' : ''}`
    }
  }

  return 'Less than 1 second'
}

function identifyHash(input) {
  const value = input.trim()
  if (!value) return { error: 'Enter a sample hash first.' }

  const matches = []

  if (/^\$argon2id\$/.test(value)) {
    const version = value.match(/\$v=(\d+)(?:\$|,)/)
    const memory = value.match(/(?:^|[, $])m=(\d+)/)
    const iterations = value.match(/(?:^|[, $])t=(\d+)/)
    const parallelism = value.match(/(?:^|[, $])p=(\d+)/)

    matches.push({
      name: 'Argon2id',
      confidence: 'Format match',
      length: `${value.length} characters`,
      details:
        `The $argon2id$ prefix indicates the Argon2id password-hashing format. ` +
        `Version: ${version ? version[1] : 'not detected'}; ` +
        `memory: ${memory ? memory[1] + ' KiB' : 'not detected'}; ` +
        `iterations: ${iterations ? iterations[1] : 'not detected'}; ` +
        `parallelism: ${parallelism ? parallelism[1] : 'not detected'}. ` +
        'This pattern-based check does not verify that the complete encoded hash is valid.',
    })
  } else if (/^\$argon2i\$/.test(value)) {
    matches.push({
      name: 'Argon2i',
      confidence: 'Format match',
      length: `${value.length} characters`,
      details: 'The $argon2i$ prefix indicates the Argon2i password-hashing variant. The encoded string has not been cryptographically validated.',
    })
  } else if (/^\$argon2d\$/.test(value)) {
    matches.push({
      name: 'Argon2d',
      confidence: 'Format match',
      length: `${value.length} characters`,
      details: 'The $argon2d$ prefix indicates the Argon2d password-hashing variant. The encoded string has not been cryptographically validated.',
    })
  } else if (/^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/.test(value)) {
    matches.push({
      name: 'bcrypt',
      confidence: 'Format match',
      length: `${value.length} characters`,
      details: 'A modular-crypt format commonly used for password hashing. The prefix includes a cost factor.',
    })
  } else if (/^\$6\$/.test(value)) {
    matches.push({
      name: 'SHA-512 crypt',
      confidence: 'Likely format',
      length: `${value.length} characters`,
      details: 'The $6$ prefix indicates the SHA-512 crypt format used by some Unix/Linux password databases.',
    })
  } else if (/^\$5\$/.test(value)) {
    matches.push({
      name: 'SHA-256 crypt',
      confidence: 'Likely format',
      length: `${value.length} characters`,
      details: 'The $5$ prefix indicates SHA-256 crypt, a modular-crypt password-hashing format.',
    })
  } else if (/^\$1\$/.test(value)) {
    matches.push({
      name: 'MD5 crypt',
      confidence: 'Likely format',
      length: `${value.length} characters`,
      details: 'The $1$ prefix indicates the older MD5 crypt password-hashing format.',
    })
  } else if (/^[a-fA-F0-9]+$/.test(value)) {
    const length = value.length

    if (length === 32) {
      matches.push({
        name: 'MD5 or NTLM',
        confidence: 'Ambiguous',
        length: '32 hexadecimal characters',
        details: 'Both MD5 digests and NTLM hashes can be represented by 32 hexadecimal characters. Length alone cannot distinguish them.',
      })
    } else if (length === 40) {
      matches.push({
        name: 'SHA-1',
        confidence: 'Length match',
        length: '40 hexadecimal characters',
        details: 'A 160-bit digest is commonly represented as 40 hexadecimal characters. Other formats may also use this length.',
      })
    } else if (length === 64) {
      matches.push({
        name: 'SHA-256',
        confidence: 'Length match',
        length: '64 hexadecimal characters',
        details: 'A SHA-256 digest is commonly represented as 64 hexadecimal characters. Length alone does not prove the algorithm.',
      })
    } else if (length === 96) {
      matches.push({
        name: 'SHA-384',
        confidence: 'Length match',
        length: '96 hexadecimal characters',
        details: 'A SHA-384 digest is commonly represented as 96 hexadecimal characters.',
      })
    } else if (length === 128) {
      matches.push({
        name: 'SHA-512',
        confidence: 'Length match',
        length: '128 hexadecimal characters',
        details: 'A SHA-512 digest is commonly represented as 128 hexadecimal characters.',
      })
    } else {
      return {
        error: `The input has ${length} hexadecimal characters. This tool has no common-format match for that length.`,
      }
    }
  } else {
    return {
      error: 'No supported format pattern matched. Check the sample for missing characters or use a supported lab example.',
    }
  }

  return { value, matches }
}

function App() {
  const [active, setActive] = useState('analyzer')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [result, setResult] = useState(null)
  const [customWords, setCustomWords] = useState('')
  const [years, setYears] = useState('')
  const [includeCommon, setIncludeCommon] = useState(true)
  const [caseVariants, setCaseVariants] = useState(true)
  const [leet, setLeet] = useState(false)
  const [numbers, setNumbers] = useState(true)
  const [wordlist, setWordlist] = useState([])
  const [dictionaryError, setDictionaryError] = useState('')
  const [lowercase, setLowercase] = useState(true)
  const [uppercase, setUppercase] = useState(true)
  const [digits, setDigits] = useState(true)
  const [symbols, setSymbols] = useState(false)
  const [simLength, setSimLength] = useState(8)
  const [guessRate, setGuessRate] = useState('1000000')
  const [simResult, setSimResult] = useState(null)
  const [simError, setSimError] = useState('')
  const [hashInput, setHashInput] = useState('')
  const [hashResult, setHashResult] = useState(null)
  const [shadowInput, setShadowInput] = useState('')
  const [shadowResult, setShadowResult] = useState(null)
  const [shadowError, setShadowError] = useState('')
  const [shadowLoading, setShadowLoading] = useState(false)
  const [windowsFile, setWindowsFile] = useState(null)
  const [windowsResult, setWindowsResult] = useState(null)
  const [windowsError, setWindowsError] = useState('')
  const [windowsLoading, setWindowsLoading] = useState(false)

  const selected = modules.find((item) => item.id === active)

  async function analyzePassword(event) {
    event.preventDefault()
    setResult(null)

    if (!password) {
      setResult({ error: 'Please enter a test password.' })
      return
    }

    try {
      const response = await fetch('http://127.0.0.1:8000/analyze-password', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password }),
      })

      const data = await response.json()
      if (!response.ok) throw new Error(data.detail || 'Analysis failed')
      setResult(data)
    } catch {
      setResult({ error: 'Backend analysis is not available. Check that the backend is running.' })
    }
  }

  function handleGenerate(event) {
    event.preventDefault()
    setDictionaryError('')

    const words = customWords
      .split(/[\n,]+/)
      .map((word) => word.trim())
      .filter(Boolean)

    const parsedYears = years
      .split(/[\s,]+/)
      .map((year) => year.trim())
      .filter((year) => /^\d{2,4}$/.test(year))

    if (words.length === 0 && !includeCommon) {
      setDictionaryError('Enter at least one test word or enable common examples.')
      setWordlist([])
      return
    }

    if (words.length > 100) {
      setDictionaryError('Enter no more than 100 custom test words at a time.')
      setWordlist([])
      return
    }

    setWordlist(generateWordlist(
      [...words, ...(includeCommon ? COMMON_WORDS : [])],
      parsedYears,
      { caseVariants, leet, numbers },
    ))
  }

  function downloadWordlist() {
    if (!wordlist.length) return

    const blob = new Blob([wordlist.join('\n') + '\n'], {
      type: 'text/plain;charset=utf-8',
    })

    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = 'password-test-wordlist.txt'
    document.body.appendChild(link)
    link.click()
    link.remove()
    URL.revokeObjectURL(url)
  }

  function runSimulation(event) {
    event.preventDefault()
    setSimError('')
    setSimResult(null)

    let poolSize = 0
    if (lowercase) poolSize += 26
    if (uppercase) poolSize += 26
    if (digits) poolSize += 10
    if (symbols) poolSize += 32

    const rate = Number(guessRate)

    if (poolSize === 0) {
      setSimError('Select at least one character set.')
      return
    }

    if (!Number.isFinite(rate) || rate <= 0 || rate > 1e15) {
      setSimError('Enter a guessing rate between 1 and 1,000,000,000,000,000.')
      return
    }

    const combinations = BigInt(poolSize) ** BigInt(simLength)
    setSimResult({
      poolSize,
      length: simLength,
      combinations: combinations.toLocaleString('en-US'),
      duration: formatDuration(Number(combinations) / rate),
      rate: rate.toLocaleString('en-US'),
    })
  }

  function runHashAnalysis(event) {
    event.preventDefault()
    setHashResult(identifyHash(hashInput))
  }

  function loadHashSample(value) {
    setHashInput(value)
    setHashResult(identifyHash(value))
  }

  async function runShadowAnalysis(event) {
    event.preventDefault()
    setShadowError('')
    setShadowResult(null)

    if (!shadowInput.trim()) {
      setShadowError('Paste sample shadow-file content or choose a text file first.')
      return
    }

    setShadowLoading(true)

    try {
      const response = await fetch('http://127.0.0.1:8000/extract/linux-shadow', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ content: shadowInput }),
      })

      const data = await response.json()

      if (!response.ok) {
        const detail = Array.isArray(data.detail)
          ? data.detail.map((item) => item.msg).join('; ')
          : data.detail
        throw new Error(detail || 'Shadow-file parsing failed.')
      }

      setShadowResult(data)
    } catch (error) {
      setShadowError(error.message || 'Could not connect to the backend. Check that FastAPI is running.')
    } finally {
      setShadowLoading(false)
    }
  }

  async function runWindowsAnalysis(event) {
    event.preventDefault()
    setWindowsError('')
    setWindowsResult(null)

    if (!windowsFile) {
      setWindowsError('Choose an offline registry-hive file named SAM or SYSTEM.')
      return
    }

    if (!['sam', 'system'].includes(windowsFile.name.toLowerCase())) {
      setWindowsError('The selected file must be named exactly SAM or SYSTEM.')
      return
    }

    setWindowsLoading(true)

    try {
      const formData = new FormData()
      formData.append('file', windowsFile)

      const response = await fetch('http://127.0.0.1:8000/analyze/windows-artifact', {
        method: 'POST',
        body: formData,
      })

      const data = await response.json()

      if (!response.ok) {
        const detail = Array.isArray(data.detail)
          ? data.detail.map((item) => item.msg).join('; ')
          : data.detail
        throw new Error(detail || 'Windows artifact analysis failed.')
      }

      setWindowsResult(data)
    } catch (error) {
      setWindowsError(error.message || 'Could not connect to the backend. Check that FastAPI is running.')
    } finally {
      setWindowsLoading(false)
    }
  }

  async function loadShadowFile(event) 
  {
    const file = event.target.files?.[0]
    if (!file) return

    setShadowError('')
    setShadowResult(null)

    if (file.size > 500000) {
      setShadowError('Choose a text file smaller than 500 KB.')
      event.target.value = ''
      return
    }

    try {
      setShadowInput(await file.text())
    } catch {
      setShadowError('The selected file could not be read.')
    }
  }
    function buildAuditReport() {
    const lines = []
    const timestamp = new Date().toLocaleString()

    function addSection(title, content) {
      lines.push('', '='.repeat(60), title.toUpperCase(), '='.repeat(60))
      lines.push(content)
    }

    function formatList(items) {
      return items?.length
        ? items.map((item) => `- ${item}`).join('\n')
        : '- No findings or recommendations were returned.'
    }

    lines.push(
      'PASSWORD SECURITY SUITE',
      'SECURITY AUDIT REPORT',
      `Generated: ${timestamp}`,
      'Assessment type: Educational, authorized laboratory assessment',
      '',
      'SCOPE AND LIMITATIONS',
      '- This report contains only results available in the current browser session.',
      '- Unexecuted modules are marked as not run.',
      '- Hash identification is pattern-based, not cryptographic verification.',
      '- Brute-force results are theoretical estimates, not actual password cracking.',
      '- Linux shadow analysis processes supplied content only.',
      '- Windows analysis checks a registry-hive header; it does not extract hashes.',
    )

    addSection(
      '1. Password Strength Analysis',
      result && !result.error
        ? [
            `Strength: ${result.strength ?? 'Not provided'}`,
            `Password length: ${result.length ?? 'Not provided'}`,
            `Estimated entropy: ${result.entropy_bits ?? 'Not provided'} bits`,
            '',
            'Findings:',
            formatList(result.findings),
            '',
            'Recommendations:',
            formatList(result.recommendations),
          ].join('\n')
        : result?.error
          ? `Analysis was attempted but did not complete successfully: ${result.error}`
          : 'Status: Not run.',
    )

    addSection(
      '2. Brute-Force Simulation',
      simResult
        ? [
            'Status: Completed — theoretical calculation only.',
            `Character pool size: ${simResult.poolSize}`,
            `Sample password length: ${simResult.length}`,
            `Possible combinations: ${simResult.combinations}`,
            `Assumed guesses per second: ${simResult.rate}`,
            `Estimated full search duration: ${simResult.duration}`,
            'No password guesses were executed.',
          ].join('\n')
        : 'Status: Not run.',
    )

    addSection(
      '3. Hash Format Analysis',
      hashResult
        ? hashResult.error
          ? `Analysis attempted but no format was identified: ${hashResult.error}`
          : [
              `Input length: ${hashResult.value?.length ?? 'Not provided'} characters`,
              ...(hashResult.matches || []).flatMap((match) => [
                '',
                `Format: ${match.name}`,
                `Confidence: ${match.confidence}`,
                `Representation: ${match.length}`,
                `Details: ${match.details}`,
              ]),
              '',
              'Note: Pattern matching does not prove the algorithm or recover a password.',
            ].join('\n')
        : 'Status: Not run.',
    )

    addSection(
      '4. Linux Shadow Analysis',
      shadowResult
        ? [
            `Records found: ${shadowResult.records_found ?? 'Not provided'}`,
            '',
            'Parser note:',
            shadowResult.note || 'No additional note provided.',
            '',
            'Warnings:',
            formatList(shadowResult.warnings),
            '',
            'Record summary:',
            ...(shadowResult.records || []).map(
              (record) =>
                `- User: ${record.username}; Format: ${record.format}; Confidence: ${record.confidence}; Status: ${record.status}; Details: ${record.details}`,
            ),
          ].join('\n')
        : shadowError
          ? `Analysis attempted but did not complete successfully: ${shadowError}`
          : 'Status: Not run.',
    )

    addSection(
      '5. Windows SAM/SYSTEM Artifact Analysis',
      windowsResult
        ? [
            `File: ${windowsResult.filename}`,
            `Size: ${windowsResult.size_bytes} bytes`,
            `Status: ${windowsResult.status}`,
            `Artifact type: ${windowsResult.artifact_type}`,
            '',
            'Findings:',
            formatList(windowsResult.findings),
            '',
            `Backend note: ${windowsResult.note || 'No additional note provided.'}`,
            'Limitation: Only a basic header check is implemented. No registry data or password hashes were extracted.',
          ].join('\n')
        : windowsError
          ? `Analysis attempted but did not complete successfully: ${windowsError}`
          : 'Status: Not run.',
    )

    addSection(
      '6. Dictionary Generator',
      wordlist.length
        ? [
            'Status: Generated.',
            `Unique entries generated: ${wordlist.length}`,
            'The generated wordlist was not automatically tested against any account or hash.',
          ].join('\n')
        : 'Status: No wordlist generated in this session.',
    )

    addSection(
      '7. Overall Assessment',
      [
        'This report summarizes the available module outputs; it is not a certification of system security.',
        'Review the findings and recommendations from the password analysis and any supplied artifact results.',
        'Do not interpret unrun modules or incomplete artifact checks as passing security tests.',
        '',
        'General recommendations:',
        '- Use long, unique passwords and a password manager.',
        '- Enable multifactor authentication where available.',
        '- Use modern password-hashing algorithms with appropriate parameters.',
        '- Protect credential files and restrict access to authorized personnel.',
        '- Preserve original forensic artifacts and document the source of test data.',
        '- Repeat assessments after significant security changes.',
      ].join('\n'),
    )

    return lines.join('\n')
  }

  function downloadAuditReport() 
  {
    const report = buildAuditReport()
    const blob = new Blob([report], { type: 'text/plain;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')

    link.href = url
    link.download = 'security-audit-report.txt'
    document.body.appendChild(link)
    link.click()
    link.remove()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-symbol">P</div>
          <div>
            <h2>Password Security</h2>
            <span>CRACKING &amp; AUDIT SUITE</span>
          </div>
        </div>
        <div className="sidebar-label">ANALYSIS TOOLS</div>
        <nav className="navigation">
          {modules.map((item) => (
            <button
              key={item.id}
              className={`nav-item ${active === item.id ? 'selected' : ''}`}
              onClick={() => setActive(item.id)}
            >
              <span className="nav-icon">{item.icon}</span>
              <span>{item.name}</span>
            </button>
          ))}
        </nav>
        <div className="sidebar-bottom">
          <span className="online-dot" />
          <div>
            <strong>Local Lab</strong>
            <small>Controlled environment</small>
          </div>
        </div>
      </aside>
      <main className="main-area">
        <header className="topbar">
          <div className="breadcrumb">Security Suite <span>/</span> {selected.name}</div>
          <div className="lab-tag"><span /> AUTHORIZED LAB</div>
        </header>
        <div className="content">
          <div className="page-heading">
            <div className="eyebrow">PASSWORD CRACKING &amp; CREDENTIAL ATTACK SUITE</div>
            <h1>{selected.name}</h1>
            <p>{selected.description}</p>
          </div>

          {active === 'analyzer' && (
            <section className="panel">
              <div className="panel-heading">
                <div>
                  <h2>Password Analysis</h2>
                  <p>Evaluate a sample password's security.</p>
                </div>
                <div className="panel-icon">◈</div>
              </div>
              <form onSubmit={analyzePassword}>
                <label htmlFor="password">TEST PASSWORD</label>
                <div className="password-input-wrapper">
                  <input
                    id="password"
                    type={showPassword ? 'text' : 'password'}
                    value={password}
                    onChange={(event) => setPassword(event.target.value)}
                    placeholder="Enter a sample password..."
                    autoComplete="off"
                  />
                  <button
                    type="button"
                    className="password-visibility-button"
                    onClick={() => setShowPassword((visible) => !visible)}
                    aria-label={showPassword ? 'Hide password' : 'Show password'}
                    title={showPassword ? 'Hide password' : 'Show password'}
                  >
                    {showPassword ? (
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                        <path d="M3 3l18 18" />
                        <path d="M10.6 10.6a2 2 0 002.8 2.8" />
                        <path d="M9.9 5.2A10.8 10.8 0 0112 5c5 0 8.5 4.5 9.5 7-.4 1-1.2 2.2-2.4 3.4" />
                        <path d="M6.2 6.2C3.9 7.7 2.5 10 2 12c1 2.5 4.5 7 10 7 1.3 0 2.5-.3 3.6-.8" />
                      </svg>
                    ) : (
                      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                        <path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z" />
                        <circle cx="12" cy="12" r="3" />
                      </svg>
                    )}
                  </button>
                </div>
                <p className="input-hint">Use a sample password, not a password from a real account.</p>
                <button className="primary-button" type="submit">Analyze Password <span>→</span></button>
              </form>
              {result && (
                <div className="result-box" aria-live="polite">
                  {result.error ? <p className="error-message">{result.error}</p> : (
                    <>
                      <h3>Analysis Results</h3>
                      <p>Strength: <strong>{result.strength}</strong></p>
                      <p>Length: {result.length} characters</p>
                      <p>Estimated entropy: {result.entropy_bits} bits</p>
                      <h4>Findings</h4>
                      <ul>{(result.findings || []).map((item, i) => <li key={i}>{item}</li>)}</ul>
                      <h4>Recommendations</h4>
                      <ul>{(result.recommendations || []).map((item, i) => <li key={i}>{item}</li>)}</ul>
                    </>
                  )}
                </div>
              )}
            </section>
          )}

          {active === 'dictionary' && (
            <section className="panel">
              <div className="panel-heading">
                <div>
                  <h2>Dictionary Generator</h2>
                  <p>Create wordlists for authorized password-security testing.</p>
                </div>
                <div className="panel-icon">▤</div>
              </div>
              <form onSubmit={handleGenerate}>
                <label htmlFor="custom-words">CUSTOM TEST WORDS</label>
                <textarea
                  id="custom-words"
                  rows="4"
                  value={customWords}
                  onChange={(event) => setCustomWords(event.target.value)}
                  placeholder="Enter sample words, one per line or separated by commas"
                />
                <label htmlFor="years" className="dictionary-label">OPTIONAL YEAR / NUMBER PATTERNS</label>
                <input
                  id="years"
                  value={years}
                  onChange={(event) => setYears(event.target.value)}
                  placeholder="Example: 2001, 2024"
                />
                <div className="dictionary-options">
                  <label className="checkbox-option"><input type="checkbox" checked={includeCommon} onChange={(event) => setIncludeCommon(event.target.checked)} /> Include common examples</label>
                  <label className="checkbox-option"><input type="checkbox" checked={caseVariants} onChange={(event) => setCaseVariants(event.target.checked)} /> Uppercase / lowercase variants</label>
                  <label className="checkbox-option"><input type="checkbox" checked={leet} onChange={(event) => setLeet(event.target.checked)} /> Leetspeak mutations</label>
                  <label className="checkbox-option"><input type="checkbox" checked={numbers} onChange={(event) => setNumbers(event.target.checked)} /> Append number patterns</label>
                </div>
                {dictionaryError && <p className="error-message">{dictionaryError}</p>}
                <button className="primary-button" type="submit">Generate Wordlist <span>→</span></button>
              </form>
              {wordlist.length > 0 && (
                <div className="result-box dictionary-results">
                  <div className="dictionary-result-heading">
                    <div><h3>Generated Wordlist</h3><p>{wordlist.length} unique test entries</p></div>
                    <button className="secondary-button" type="button" onClick={downloadWordlist}>Download .txt</button>
                  </div>
                  <textarea readOnly rows="10" value={wordlist.join('\n')} aria-label="Generated wordlist preview" />
                </div>
              )}
            </section>
          )}

          {active === 'simulator' && (
            <section className="panel">
              <div className="panel-heading">
                <div><h2>Search Space Simulation</h2><p>Estimate theoretical combinations for a sample password configuration.</p></div>
                <div className="panel-icon">⚡</div>
              </div>
              <form onSubmit={runSimulation}>
                <label>CHARACTER SETS</label>
                <div className="dictionary-options simulator-options">
                  <label className="checkbox-option"><input type="checkbox" checked={lowercase} onChange={(event) => setLowercase(event.target.checked)} /> Lowercase (a–z)</label>
                  <label className="checkbox-option"><input type="checkbox" checked={uppercase} onChange={(event) => setUppercase(event.target.checked)} /> Uppercase (A–Z)</label>
                  <label className="checkbox-option"><input type="checkbox" checked={digits} onChange={(event) => setDigits(event.target.checked)} /> Digits (0–9)</label>
                  <label className="checkbox-option"><input type="checkbox" checked={symbols} onChange={(event) => setSymbols(event.target.checked)} /> Symbols (32 representative characters)</label>
                </div>
                <label htmlFor="sim-length">SAMPLE PASSWORD LENGTH: {simLength}</label>
                <input id="sim-length" type="range" min="1" max="32" value={simLength} onChange={(event) => setSimLength(Number(event.target.value))} />
                <div className="simulator-range-labels"><span>1 character</span><span>32 characters</span></div>
                <label htmlFor="guess-rate">THEORETICAL GUESSES PER SECOND</label>
                <input id="guess-rate" type="number" min="1" max="1000000000000000" step="any" value={guessRate} onChange={(event) => setGuessRate(event.target.value)} required />
                <p className="input-hint">Default: 1,000,000 guesses per second. Illustrative assumption, not a benchmark.</p>
                {simError && <p className="error-message">{simError}</p>}
                <button className="primary-button" type="submit">Calculate Search Space <span>→</span></button>
              </form>
              {simResult && (
                <div className="result-box simulator-results" aria-live="polite">
                  <div className="simulator-result-top">
                    <div><h3>Simulation Results</h3><p>Theoretical estimate only — no password guesses were executed.</p></div>
                    <span className="simulation-badge">CALCULATED</span>
                  </div>
                  <div className="simulator-stat-grid">
                    <div className="simulator-stat"><span>Character pool</span><strong>{simResult.poolSize}</strong></div>
                    <div className="simulator-stat"><span>Password length</span><strong>{simResult.length}</strong></div>
                    <div className="simulator-stat"><span>Possible combinations</span><strong>{simResult.combinations}</strong></div>
                    <div className="simulator-stat"><span>Assumed rate</span><strong>{simResult.rate}/sec</strong></div>
                  </div>
                  <div className="simulator-time-result"><span>Estimated time to search the entire space</span><strong>{simResult.duration}</strong></div>
                  <div className="simulator-progress-track" role="progressbar" aria-valuenow="100" aria-valuemin="0" aria-valuemax="100" aria-label="Calculation completed"><div className="simulator-progress-fill" /></div>
                  <p className="input-hint">Calculation complete. Actual time depends on hardware, hash algorithm, rate limits and password choice.</p>
                </div>
              )}
            </section>
          )}

          {active === 'hashes' && (
            <section className="panel">
              <div className="panel-heading">
                <div><h2>Hash Format Analyzer</h2><p>Inspect sample hashes and identify possible formats from their structure.</p></div>
                <div className="panel-icon">#</div>
              </div>
              <form onSubmit={runHashAnalysis}>
                <label htmlFor="hash-input">SAMPLE HASH</label>
                <textarea
                  id="hash-input"
                  rows="3"
                  value={hashInput}
                  onChange={(event) => {
                    setHashInput(event.target.value)
                    setHashResult(null)
                  }}
                  placeholder="Paste an authorized lab hash here..."
                  spellCheck="false"
                  autoComplete="off"
                />
                <p className="input-hint">Use test samples only. A hash string is not necessarily a password, and format detection does not recover the original value.</p>
                <button className="primary-button" type="submit">Identify Hash Format <span>→</span></button>
              </form>
              <div className="hash-samples">
                <h3>Try a sample</h3>
                <p>Choose a format-shaped example to test the identifier.</p>
                <div className="hash-sample-list">
                  {HASH_SAMPLES.map((sample) => (
                    <button
                      key={sample.name}
                      type="button"
                      className="hash-sample-button"
                      onClick={() => loadHashSample(sample.value)}
                    >
                      <span>{sample.name}</span><span>Use sample →</span>
                    </button>
                  ))}
                </div>
              </div>
              {hashResult && (
                <div className="result-box hash-results" aria-live="polite">
                  {hashResult.error ? (
                    <p className="error-message">{hashResult.error}</p>
                  ) : (
                    <>
                      <h3>Identification Results</h3>
                      <p className="input-hint">Input length: {hashResult.value.length} characters</p>
                      {hashResult.matches.map((match) => (
                        <div className="hash-match" key={match.name}>
                          <div className="hash-match-heading">
                            <h4>{match.name}</h4>
                            <span className="simulation-badge">{match.confidence}</span>
                          </div>
                          <p><strong>Typical representation:</strong> {match.length}</p>
                          <p>{match.details}</p>
                        </div>
                      ))}
                      <p className="hash-caveat">This is pattern-based identification, not cryptographic verification. Different algorithms can share the same output length and character set. A sample's context and metadata may be necessary for reliable identification.</p>
                    </>
                  )}
                </div>
              )}
            </section>
          )}

          {active === 'shadow' && (
            <section className="panel">
              <div className="panel-heading">
                <div>
                  <h2>Linux Shadow File Parser</h2>
                  <p>Parse supplied offline lab content and inspect likely password-hash formats.</p>
                </div>
                <div className="panel-icon">▥</div>
              </div>
              <form onSubmit={runShadowAnalysis}>
                <label htmlFor="shadow-file">OPTIONAL TEXT FILE (.TXT)</label>
                <input id="shadow-file" type="file" accept=".txt,text/plain" onChange={loadShadowFile} />
                <p className="input-hint">The file is read in this browser and its text is sent to your local backend. Use synthetic or authorized offline lab data only.</p>
                <label htmlFor="shadow-content">SHADOW-FILE SAMPLE CONTENT</label>
                <textarea
                  id="shadow-content"
                  rows="8"
                  value={shadowInput}
                  onChange={(event) => {
                    setShadowInput(event.target.value)
                    setShadowResult(null)
                    setShadowError('')
                  }}
                  placeholder={`Paste sample lines here, for example:
labuser:$6$rounds=5000$sampleSalt$exampleHashValue:20000:0:99999:7:::
lockeduser:!:20000:0:99999:7:::`}
                  spellCheck="false"
                  autoComplete="off"
                />
                {shadowError && <p className="error-message" role="alert">{shadowError}</p>}
                <button className="primary-button" type="submit" disabled={shadowLoading}>
                  {shadowLoading ? 'Analyzing…' : 'Parse Shadow Sample'} <span>→</span>
                </button>
              </form>
              {shadowResult && (
                <div className="result-box" aria-live="polite">
                  <h3>Parsing Results</h3>
                  <p>Records found: <strong>{shadowResult.records_found}</strong></p>
                  {shadowResult.note && <p className="input-hint">{shadowResult.note}</p>}
                  {shadowResult.warnings?.length > 0 && (
                    <>
                      <h4>Warnings</h4>
                      <ul>{shadowResult.warnings.map((warning, index) => <li key={index}>{warning}</li>)}</ul>
                    </>
                  )}
                  {shadowResult.records?.length > 0 ? (
                    <div className="shadow-table-wrap">
                      <table className="shadow-table">
                        <thead>
                          <tr>
                            <th>Username</th>
                            <th>Detected format</th>
                            <th>Confidence</th>
                            <th>Status</th>
                            <th>Details</th>
                          </tr>
                        </thead>
                        <tbody>
                          {shadowResult.records.map((record, index) => (
                            <tr key={`${record.username}-${index}`}>
                              <td>{record.username}</td>
                              <td>{record.format}</td>
                              <td>{record.confidence}</td>
                              <td>{record.status}</td>
                              <td>{record.details}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  ) : <p>No records were returned by the parser.</p>}
                  <p className="hash-caveat">Format detection is heuristic only. It does not validate hashes or recover passwords. This tool parses only the content supplied; it does not access the computer's protected /etc/shadow file.</p>
                </div>
              )}
            </section>
          )}

          {active === 'windows' && (
            <section className="panel">
              <div className="panel-heading">
                <div>
                  <h2>Windows SAM/SYSTEM Artifact Analyzer</h2>
                  <p>Inspect the basic header of a supplied offline Windows registry hive.</p>
                </div>
                <div className="panel-icon">▦</div>
              </div>
              <form onSubmit={runWindowsAnalysis}>
                <label htmlFor="windows-artifact">OFFLINE REGISTRY HIVE (FILE MUST BE NAMED SAM OR SYSTEM)</label>
                <input
                  id="windows-artifact"
                  type="file"
                  accept="*/*"
                  onChange={(event) => {
                    setWindowsFile(event.target.files?.[0] || null)
                    setWindowsResult(null)
                    setWindowsError('')
                  }}
                />
                <p className="input-hint">
                  Select an authorized offline copy of a Windows registry hive. Do not upload live system files or data you are not authorized to examine.
                </p>
                {windowsError && <p className="error-message" role="alert">{windowsError}</p>}
                <button className="primary-button" type="submit" disabled={windowsLoading}>
                  {windowsLoading ? 'Analyzing…' : 'Analyze Windows Artifact'} <span>→</span>
                </button>
              </form>
              {windowsResult && (
                <div className="result-box" aria-live="polite">
                  <h3>Artifact Analysis Results</h3>
                  <p>File: <strong>{windowsResult.filename}</strong></p>
                  <p>Size: {Number(windowsResult.size_bytes).toLocaleString('en-US')} bytes</p>
                  <p>Status: <strong>{windowsResult.status}</strong></p>
                  <p>Artifact type: {windowsResult.artifact_type}</p>
                  <h4>Findings</h4>
                  <ul>
                    {(windowsResult.findings || []).map((finding, index) => <li key={index}>{finding}</li>)}
                  </ul>
                  {windowsResult.note && <p className="hash-caveat">{windowsResult.note}</p>}
                  <p className="hash-caveat">
                    Important: this version performs only a basic registry-hive header check. It does not parse SAM/SYSTEM registry data or extract password hashes.
                  </p>
                </div>
              )}
            </section>
          )}

          {active === 'reports' && (
            <section className="panel">
              <div className="panel-heading">
                <div>
                 <h2>Security Audit Report</h2>
                 <p>Review the assessment results collected during this browser session.</p>
                </div>
                <div className="panel-icon">▧</div>
              </div>

    <div className="result-box">
      <h3>Assessment Status</h3>

      <p>
        Password analysis:{' '}
        <strong>
          {result && !result.error ? 'Completed' : 'Not completed'}
        </strong>
      </p>

      <p>
        Dictionary generator:{' '}
        <strong>
          {wordlist.length > 0 ? 'Wordlist generated' : 'Not generated'}
        </strong>
      </p>

      <p>
        Brute-force simulation:{' '}
        <strong>{simResult ? 'Completed' : 'Not run'}</strong>
      </p>

      <p>
        Hash analyzer:{' '}
        <strong>{hashResult ? 'Run' : 'Not run'}</strong>
      </p>

      <p>
        Linux shadow analyzer:{' '}
        <strong>{shadowResult ? 'Completed' : 'Not completed'}</strong>
      </p>

      <p>
        Windows artifact analyzer:{' '}
        <strong>{windowsResult ? 'Completed' : 'Not completed'}</strong>
      </p>
    </div>

    <div className="panel-heading">
      <div>
        <h3>Report Preview</h3>
        <p>
          The report includes available results, limitations, and
          recommendations.
        </p>
      </div>
    </div>

    <textarea
      className="audit-report-preview"
      aria-label="Security audit report preview"
      readOnly
      rows={22}
      value={buildAuditReport()}
    />

    <p className="input-hint">
      Save the report as a text file for your project documentation.
      Only results currently available in this session are included.
    </p>

    <button
      className="primary-button"
      type="button"
      onClick={downloadAuditReport}
    >
      Download Security Audit Report <span>↓</span>
    </button>
  </section>
)}

          <div className="notice"><span>ⓘ</span> Use only authorized test data and controlled laboratory environments.</div>
        </div>
        <footer className="footer"><span>Password Security Suite</span><span>Educational Security Assessment</span></footer>
      </main>
    </div>
  )
}

export default App
