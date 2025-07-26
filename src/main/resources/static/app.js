const { useState, useEffect, useMemo } = React;

// --- API Configuration ---
const API_BASE_URL = 'http://localhost:8080/api/v1';

// --- Helper Functions ---
const api = {
    uploadKeystore: (file, password, sessionId) => {
        const formData = new FormData();
        formData.append('keystoreFile', file);
        formData.append('keystorePassword', password);
        formData.append('sessionId', sessionId);
        return fetch(`${API_BASE_URL}/keystore/upload`, { method: 'POST', body: formData });
    },
    createKeystore: (password, sessionId) => {
        return fetch(`${API_BASE_URL}/keystore/create`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password, sessionId }),
        });
    },
    createKeyPair: (data) => {
         return fetch(`${API_BASE_URL}/keystore/create-keypair`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data),
        });
    },
    deleteEntry: (alias, sessionId) => {
        return fetch(`${API_BASE_URL}/keystore/entry/${alias}?sessionId=${sessionId}`, { method: 'DELETE' });
    },
    exportPrivateKey: (data) => {
        return fetch(`${API_BASE_URL}/keystore/export-private-key`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(data),
        });
    },
};

// --- UI Components ---

const Header = () => (
    <header className="bg-white dark:bg-slate-800/80 backdrop-blur-md shadow-sm sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
            <div className="flex items-center justify-between h-16">
                <div className="flex items-center space-x-3">
                    <i className="fas fa-shield-halved text-2xl text-indigo-600 dark:text-indigo-400"></i>
                    <span className="text-xl font-bold text-slate-800 dark:text-slate-200">Crypto Command Center</span>
                </div>
            </div>
        </div>
    </header>
);

const WelcomeScreen = ({ handleCreate, handleUpload, setLoading, setError }) => {
    const [password, setPassword] = useState('');
    const [file, setFile] = useState(null);
    const [uploadPassword, setUploadPassword] = useState('');

    const onFileChange = (e) => {
        if (e.target.files.length > 0) {
            setFile(e.target.files[0]);
        }
    };

    const submitCreate = (e) => {
        e.preventDefault();
        if (password) {
            handleCreate(password);
        } else {
            setError("Password cannot be empty.");
        }
    };

    const submitUpload = (e) => {
        e.preventDefault();
        if (file && uploadPassword) {
            handleUpload(file, uploadPassword);
        } else {
            setError("Please select a file and provide a password.");
        }
    };

    return (
        <div className="mt-10 max-w-4xl mx-auto grid grid-cols-1 md:grid-cols-2 gap-8">
            <div className="bg-white dark:bg-slate-800 p-8 rounded-xl shadow-lg border border-slate-200 dark:border-slate-700">
                <h2 className="text-2xl font-bold text-slate-900 dark:text-white mb-1">Create New Keystore</h2>
                <p className="text-slate-500 dark:text-slate-400 mb-6">Start with a fresh, empty keystore.</p>
                <form onSubmit={submitCreate}>
                    <label htmlFor="new-password" className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">Keystore Password</label>
                    <input
                        id="new-password"
                        type="password"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        className="w-full px-3 py-2 bg-white dark:bg-slate-700 border border-slate-300 dark:border-slate-600 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500"
                        placeholder="Enter a strong password"
                    />
                    <button type="submit" className="w-full mt-4 bg-indigo-600 text-white font-semibold py-2 px-4 rounded-md hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 transition">
                        <i className="fas fa-plus-circle mr-2"></i>Create Keystore
                    </button>
                </form>
            </div>
            <div className="bg-white dark:bg-slate-800 p-8 rounded-xl shadow-lg border border-slate-200 dark:border-slate-700">
                <h2 className="text-2xl font-bold text-slate-900 dark:text-white mb-1">Load Existing Keystore</h2>
                <p className="text-slate-500 dark:text-slate-400 mb-6">Upload a .jks file to manage it.</p>
                <form onSubmit={submitUpload}>
                    <div className="space-y-4">
                        <div>
                            <label htmlFor="upload-file" className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">JKS File</label>
                            <input
                                id="upload-file"
                                type="file"
                                onChange={onFileChange}
                                accept=".jks"
                                className="block w-full text-sm text-slate-500 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-sm file:font-semibold file:bg-indigo-50 dark:file:bg-indigo-900/50 file:text-indigo-700 dark:file:text-indigo-300 hover:file:bg-indigo-100 dark:hover:file:bg-indigo-900"
                            />
                        </div>
                        <div>
                            <label htmlFor="upload-password" className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">Keystore Password</label>
                            <input
                                id="upload-password"
                                type="password"
                                value={uploadPassword}
                                onChange={(e) => setUploadPassword(e.target.value)}
                                className="w-full px-3 py-2 bg-white dark:bg-slate-700 border border-slate-300 dark:border-slate-600 rounded-md focus:outline-none focus:ring-2 focus:ring-indigo-500"
                                placeholder="Password for the keystore"
                            />
                        </div>
                    </div>
                    <button type="submit" className="w-full mt-4 bg-slate-600 text-white font-semibold py-2 px-4 rounded-md hover:bg-slate-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-slate-500 transition">
                        <i className="fas fa-upload mr-2"></i>Upload & Manage
                    </button>
                </form>
            </div>
        </div>
    );
};

const CertificateTable = ({ certificates, handleDelete, handleExport }) => {
    if (certificates.length === 0) {
        return (
            <div className="text-center py-12 border-2 border-dashed border-slate-300 dark:border-slate-700 rounded-lg">
                <i className="fas fa-box-open text-4xl text-slate-400 dark:text-slate-500 mb-4"></i>
                <h3 className="text-xl font-semibold text-slate-700 dark:text-slate-300">Keystore is Empty</h3>
                <p className="text-slate-500 dark:text-slate-400 mt-1">Create a key pair or import a certificate to get started.</p>
            </div>
        );
    }

    const formatDate = (dateString) => new Date(dateString).toLocaleDateString('en-CA');

    const getStatusBadge = (status) => {
        switch (status) {
            case 'VALID':
                return <span className="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800 dark:bg-green-800 dark:text-green-100">Valid</span>;
            case 'WARNING':
                return <span className="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-yellow-100 text-yellow-800 dark:bg-yellow-800 dark:text-yellow-100">Expires Soon</span>;
            case 'EXPIRED':
                return <span className="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-red-100 text-red-800 dark:bg-red-800 dark:text-red-100">Expired</span>;
            default:
                return <span className="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-200">Unknown</span>;
        }
    };

    return (
        <div className="overflow-x-auto">
            <table className="min-w-full bg-white dark:bg-slate-800 rounded-lg shadow-md">
                <thead className="bg-slate-50 dark:bg-slate-700/50">
                    <tr>
                        {['Alias', 'Subject', 'Type', 'Status', 'Expires On', 'Actions'].map(h => (
                            <th key={h} className="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-300 uppercase tracking-wider">{h}</th>
                        ))}
                    </tr>
                </thead>
                <tbody className="divide-y divide-slate-200 dark:divide-slate-700">
                    {certificates.map(cert => (
                        <tr key={cert.alias} className="hover:bg-slate-50 dark:hover:bg-slate-700/50 transition-colors">
                            <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-slate-900 dark:text-white">{cert.alias}</td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-500 dark:text-slate-400 max-w-xs truncate" title={cert.subject}>{cert.subject}</td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-500 dark:text-slate-400">{cert.entryType.includes('Key Pair') ? 'Private Key' : 'Public Key'}</td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm">{getStatusBadge(cert.status)}</td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-500 dark:text-slate-400">{formatDate(cert.notAfter)}</td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm font-medium space-x-2">
                                <button onClick={() => handleExport(cert)} className="text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-300 transition">
                                    <i className="fas fa-file-export mr-1"></i>Export
                                </button>
                                <button onClick={() => handleDelete(cert.alias)} className="text-red-600 hover:text-red-800 dark:text-red-400 dark:hover:text-red-300 transition">
                                    <i className="fas fa-trash-alt mr-1"></i>Delete
                                </button>
                            </td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    );
};

const CreateKeyPairModal = ({ isOpen, onClose, handleCreateKeyPair }) => {
    const [alias, setAlias] = useState('');
    const [keyPassword, setKeyPassword] = useState('');
    const [subjectDetails, setSubjectDetails] = useState({
        CN: 'localhost', OU: '', O: '', L: '', ST: '', C: ''
    });
    const [keySize, setKeySize] = useState('2048');
    const [sigAlg, setSigAlg] = useState('SHA256WithRSAEncryption');

    if (!isOpen) return null;

    const handleSubjectChange = (e) => {
        const { name, value } = e.target;
        setSubjectDetails(prev => ({ ...prev, [name]: value }));
    };

    const handleSubmit = (e) => {
        e.preventDefault();
        handleCreateKeyPair({ alias, keyPassword, subjectDetails, keySize, sigAlg });
        onClose();
    };

    return (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50">
            <div className="bg-white dark:bg-slate-800 rounded-lg shadow-xl p-8 w-full max-w-2xl m-4 overflow-y-auto max-h-screen">
                <h2 className="text-2xl font-bold mb-6 text-slate-900 dark:text-white">Create New Key Pair</h2>
                <form onSubmit={handleSubmit} className="space-y-4">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">Alias</label>
                            <input type="text" value={alias} onChange={e => setAlias(e.target.value)} required className="mt-1 w-full form-input"/>
                        </div>
                        <div>
                            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">Key Password</label>
                            <input type="password" value={keyPassword} onChange={e => setKeyPassword(e.target.value)} required className="mt-1 w-full form-input"/>
                        </div>
                        <div>
                            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">Common Name (CN)</label>
                            <input type="text" name="CN" value={subjectDetails.CN} onChange={handleSubjectChange} required className="mt-1 w-full form-input"/>
                        </div>
                        <div>
                            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">Organizational Unit (OU)</label>
                            <input type="text" name="OU" value={subjectDetails.OU} onChange={handleSubjectChange} className="mt-1 w-full form-input"/>
                        </div>
                        <div>
                            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">Organization (O)</label>
                            <input type="text" name="O" value={subjectDetails.O} onChange={handleSubjectChange} className="mt-1 w-full form-input"/>
                        </div>
                        <div>
                            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">City/Locality (L)</label>
                            <input type="text" name="L" value={subjectDetails.L} onChange={handleSubjectChange} className="mt-1 w-full form-input"/>
                        </div>
                        <div>
                            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">State/Province (ST)</label>
                            <input type="text" name="ST" value={subjectDetails.ST} onChange={handleSubjectChange} className="mt-1 w-full form-input"/>
                        </div>
                        <div>
                            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">Country Code (C)</label>
                            <input type="text" name="C" value={subjectDetails.C} onChange={handleSubjectChange} className="mt-1 w-full form-input"/>
                        </div>
                        <div>
                            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">Key Size</label>
                            <select value={keySize} onChange={e => setKeySize(e.target.value)} className="mt-1 w-full form-input">
                                <option value="2048">2048-bit</option>
                                <option value="4096">4096-bit</option>
                            </select>
                        </div>
                        <div>
                            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">Signature Algorithm</label>
                            <select value={sigAlg} onChange={e => setSigAlg(e.target.value)} className="mt-1 w-full form-input">
                                <option value="SHA256WithRSAEncryption">SHA256WithRSA</option>
                                <option value="SHA512WithRSAEncryption">SHA512WithRSA</option>
                            </select>
                        </div>
                    </div>
                    <div className="flex justify-end space-x-4 pt-4">
                        <button type="button" onClick={onClose} className="px-4 py-2 rounded-md text-slate-600 dark:text-slate-300 bg-slate-200 dark:bg-slate-700 hover:bg-slate-300 dark:hover:bg-slate-600 transition">Cancel</button>
                        <button type="submit" className="px-4 py-2 rounded-md text-white bg-indigo-600 hover:bg-indigo-700 transition">Create</button>
                    </div>
                </form>
            </div>
             <style>{`.form-input { padding: 0.5rem 0.75rem; border-radius: 0.375rem; border: 1px solid #cbd5e1; background-color: white; } .dark .form-input { border-color: #475569; background-color: #334155; color: white; }`}</style>
        </div>
    );
};

const ExportModal = ({ isOpen, onClose, certificate, sessionId, setError }) => {
    const [exportType, setExportType] = useState('cert');
    const [certFormat, setCertFormat] = useState('pem');
    const [keyPassword, setKeyPassword] = useState('');
    const [encryptionPassword, setEncryptionPassword] = useState('');

    useEffect(() => {
        // Reset state when a new certificate is selected for export
        setExportType('cert');
        setCertFormat('pem');
        setKeyPassword('');
        setEncryptionPassword('');
    }, [certificate]);

    if (!isOpen) return null;

    const handleExport = async () => {
        setError(null);
        if (exportType === 'cert') {
            window.open(`${API_BASE_URL}/keystore/export-cert/${certificate.alias}?format=${certFormat}&sessionId=${sessionId}`, '_blank');
        } else {
            try {
                const res = await api.exportPrivateKey({
                    sessionId,
                    alias: certificate.alias,
                    keyPassword,
                    encryptionPassword,
                });
                if (!res.ok) {
                    const err = await res.json();
                    throw new Error(err.error || 'Failed to export private key.');
                }
                const blob = await res.blob();
                const url = window.URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.style.display = 'none';
                a.href = url;
                a.download = `${certificate.alias}_key.pem`;
                document.body.appendChild(a);
                a.click();
                window.URL.revokeObjectURL(url);
                a.remove();
            } catch (err) {
                setError(err.message);
            }
        }
        onClose();
    };

    return (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50">
            <div className="bg-white dark:bg-slate-800 rounded-lg shadow-xl p-8 w-full max-w-md m-4">
                <h2 className="text-2xl font-bold mb-6 text-slate-900 dark:text-white">Export Entry: {certificate.alias}</h2>
                <div className="space-y-4">
                    <div>
                        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">Export Type</label>
                        <select value={exportType} onChange={e => setExportType(e.target.value)} className="mt-1 w-full form-input">
                            <option value="cert">Certificate Only</option>
                            {certificate.entryType.includes('Key Pair') && <option value="key">Private Key</option>}
                        </select>
                    </div>

                    {exportType === 'cert' && (
                        <div>
                            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">Certificate Format</label>
                            <select value={certFormat} onChange={e => setCertFormat(e.target.value)} className="mt-1 w-full form-input">
                                <option value="pem">PEM</option>
                                <option value="der">DER</option>
                            </select>
                        </div>
                    )}

                    {exportType === 'key' && (
                        <>
                            <div>
                                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">Key Password (for this entry)</label>
                                <input type="password" value={keyPassword} onChange={e => setKeyPassword(e.target.value)} required className="mt-1 w-full form-input" placeholder="Required to unlock the key"/>
                            </div>
                            <div>
                                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">Encryption Password (Optional)</label>
                                <input type="password" value={encryptionPassword} onChange={e => setEncryptionPassword(e.target.value)} className="mt-1 w-full form-input" placeholder="For encrypting the exported file"/>
                            </div>
                        </>
                    )}
                </div>
                <div className="flex justify-end space-x-4 pt-6">
                    <button type="button" onClick={onClose} className="px-4 py-2 rounded-md text-slate-600 dark:text-slate-300 bg-slate-200 dark:bg-slate-700 hover:bg-slate-300 dark:hover:bg-slate-600 transition">Cancel</button>
                    <button type="button" onClick={handleExport} className="px-4 py-2 rounded-md text-white bg-blue-600 hover:bg-blue-700 transition">Export</button>
                </div>
            </div>
            <style>{`.form-input { padding: 0.5rem 0.75rem; border-radius: 0.375rem; border: 1px solid #cbd5e1; background-color: white; } .dark .form-input { border-color: #475569; background-color: #334155; color: white; }`}</style>
        </div>
    );
};


const Dashboard = ({ certificates, sessionId, setCertificates, setLoading, setError, endSession }) => {
    const [isCreateModalOpen, setIsCreateModalOpen] = useState(false);
    const [exportCert, setExportCert] = useState(null);

    const handleCreateKeyPair = async (data) => {
        setLoading(true);
        setError(null);
        try {
            const res = await api.createKeyPair({ ...data, sessionId });
            const result = await res.json();
            if (!res.ok) throw new Error(result.error || 'Failed to create key pair.');
            setCertificates(result);
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    const handleDelete = async (alias) => {
        if (!confirm(`Are you sure you want to delete the entry with alias "${alias}"?`)) return;
        setLoading(true);
        setError(null);
        try {
            const res = await api.deleteEntry(alias, sessionId);
            const result = await res.json();
            if (!res.ok) throw new Error(result.error || 'Failed to delete entry.');
            setCertificates(result);
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    const downloadKeystore = () => {
        window.open(`${API_BASE_URL}/keystore/download?sessionId=${sessionId}`, '_blank');
    };

    return (
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
            <div className="flex flex-wrap justify-between items-center mb-6 gap-4">
                <h1 className="text-3xl font-bold text-slate-900 dark:text-white">Keystore Dashboard</h1>
                <div className="flex space-x-3">
                    <button onClick={() => setIsCreateModalOpen(true)} className="px-4 py-2 rounded-md text-white bg-indigo-600 hover:bg-indigo-700 transition"><i className="fas fa-key mr-2"></i>Create Key Pair</button>
                    <button onClick={downloadKeystore} className="px-4 py-2 rounded-md text-white bg-green-600 hover:bg-green-700 transition"><i className="fas fa-save mr-2"></i>Save Keystore</button>
                    <button onClick={endSession} className="px-4 py-2 rounded-md text-slate-700 bg-slate-200 hover:bg-slate-300 dark:text-slate-200 dark:bg-slate-700 dark:hover:bg-slate-600 transition"><i className="fas fa-sign-out-alt mr-2"></i>End Session</button>
                </div>
            </div>
            <CertificateTable certificates={certificates} handleDelete={handleDelete} handleExport={setExportCert} />
            <CreateKeyPairModal isOpen={isCreateModalOpen} onClose={() => setIsCreateModalOpen(false)} handleCreateKeyPair={handleCreateKeyPair} />
            {exportCert && <ExportModal isOpen={true} onClose={() => setExportCert(null)} certificate={exportCert} sessionId={sessionId} setError={setError} />}
        </div>
    );
};


// --- Main App Component ---
function App() {
    const [sessionId, setSessionId] = useState(null);
    const [certificates, setCertificates] = useState([]);
    const [isKeystoreLoaded, setIsKeystoreLoaded] = useState(false);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);

    useEffect(() => {
        setSessionId(crypto.randomUUID());
    }, []);

    const handleApiResponse = async (promise) => {
        setLoading(true);
        setError(null);
        try {
            const response = await promise;
            const result = await response.json();
            if (!response.ok) {
                throw new Error(result.error || 'An unknown error occurred.');
            }
            setCertificates(result);
            setIsKeystoreLoaded(true);
        } catch (err) {
            setError(err.message);
            setIsKeystoreLoaded(false);
        } finally {
            setLoading(false);
        }
    };

    const handleCreate = (password) => {
        handleApiResponse(api.createKeystore(password, sessionId));
    };

    const handleUpload = (file, password) => {
        handleApiResponse(api.uploadKeystore(file, password, sessionId));
    };

    const endSession = () => {
        setCertificates([]);
        setIsKeystoreLoaded(false);
        setError(null);
    };

    return (
        <div className="min-h-screen bg-slate-50 dark:bg-slate-900 text-slate-800 dark:text-slate-200">
            <Header />
            <main>
                {loading && (
                    <div className="fixed inset-0 bg-black/20 flex items-center justify-center z-50">
                        <i className="fas fa-spinner fa-spin text-white text-4xl"></i>
                    </div>
                )}
                {error && (
                    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 mt-4">
                        <div className="bg-red-100 dark:bg-red-900/50 border-l-4 border-red-500 text-red-700 dark:text-red-200 p-4 rounded-md" role="alert">
                            <p className="font-bold">Error</p>
                            <p>{error}</p>
                            <button onClick={() => setError(null)} className="absolute top-0 bottom-0 right-0 px-4 py-3">
                                <span className="text-2xl">&times;</span>
                            </button>
                        </div>
                    </div>
                )}

                {!isKeystoreLoaded ? (
                    <WelcomeScreen
                        handleCreate={handleCreate}
                        handleUpload={handleUpload}
                        setLoading={setLoading}
                        setError={setError}
                    />
                ) : (
                    <Dashboard
                        certificates={certificates}
                        sessionId={sessionId}
                        setCertificates={setCertificates}
                        setLoading={setLoading}
                        setError={setError}
                        endSession={endSession}
                    />
                )}
            </main>
        </div>
    );
}

// --- Render the App ---
const container = document.getElementById('root');
const root = ReactDOM.createRoot(container);
root.render(<App />);