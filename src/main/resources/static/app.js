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
            {/* Create New Keystore */}
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
            {/* Upload Existing Keystore */}
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

const CertificateTable = ({ certificates, handleDelete }) => {
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

    return (
        <div className="overflow-x-auto">
            <table className="min-w-full bg-white dark:bg-slate-800 rounded-lg shadow-md">
                <thead className="bg-slate-50 dark:bg-slate-700/50">
                    <tr>
                        {['Alias', 'Subject', 'Type', 'Valid From', 'Valid To', 'Actions'].map(h => (
                            <th key={h} className="px-6 py-3 text-left text-xs font-medium text-slate-500 dark:text-slate-300 uppercase tracking-wider">{h}</th>
                        ))}
                    </tr>
                </thead>
                <tbody className="divide-y divide-slate-200 dark:divide-slate-700">
                    {certificates.map(cert => (
                        <tr key={cert.alias} className="hover:bg-slate-50 dark:hover:bg-slate-700/50 transition-colors">
                            <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-slate-900 dark:text-white">{cert.alias}</td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-500 dark:text-slate-400 max-w-xs truncate" title={cert.subject}>{cert.subject}</td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-500 dark:text-slate-400">{cert.entryType}</td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-500 dark:text-slate-400">{formatDate(cert.notBefore)}</td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm text-slate-500 dark:text-slate-400">{formatDate(cert.notAfter)}</td>
                            <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
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
    const [commonName, setCommonName] = useState('localhost');
    const [keySize, setKeySize] = useState('2048');

    if (!isOpen) return null;

    const handleSubmit = (e) => {
        e.preventDefault();
        handleCreateKeyPair({ alias, keyPassword, commonName, keySize });
        onClose();
    };

    return (
        <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50">
            <div className="bg-white dark:bg-slate-800 rounded-lg shadow-xl p-8 w-full max-w-md m-4">
                <h2 className="text-2xl font-bold mb-6 text-slate-900 dark:text-white">Create New Key Pair</h2>
                <form onSubmit={handleSubmit} className="space-y-4">
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
                        <input type="text" value={commonName} onChange={e => setCommonName(e.target.value)} required className="mt-1 w-full form-input"/>
                    </div>
                     <div>
                        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300">Key Size</label>
                        <select value={keySize} onChange={e => setKeySize(e.target.value)} className="mt-1 w-full form-input">
                            <option value="2048">2048-bit</option>
                            <option value="4096">4096-bit</option>
                        </select>
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


const Dashboard = ({ certificates, sessionId, setCertificates, setLoading, setError, endSession }) => {
    const [isModalOpen, setIsModalOpen] = useState(false);

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
            <div className="flex justify-between items-center mb-6">
                <h1 className="text-3xl font-bold text-slate-900 dark:text-white">Keystore Dashboard</h1>
                <div className="flex space-x-3">
                    <button onClick={() => setIsModalOpen(true)} className="px-4 py-2 rounded-md text-white bg-indigo-600 hover:bg-indigo-700 transition"><i className="fas fa-key mr-2"></i>Create Key Pair</button>
                    <button onClick={downloadKeystore} className="px-4 py-2 rounded-md text-white bg-green-600 hover:bg-green-700 transition"><i className="fas fa-download mr-2"></i>Download Keystore</button>
                    <button onClick={endSession} className="px-4 py-2 rounded-md text-slate-700 bg-slate-200 hover:bg-slate-300 dark:text-slate-200 dark:bg-slate-700 dark:hover:bg-slate-600 transition"><i className="fas fa-sign-out-alt mr-2"></i>End Session</button>
                </div>
            </div>
            <CertificateTable certificates={certificates} handleDelete={handleDelete} />
            <CreateKeyPairModal isOpen={isModalOpen} onClose={() => setIsModalOpen(false)} handleCreateKeyPair={handleCreateKeyPair} />
        </div>
    );
};


// --- Main App Component ---
function App() {
    const [sessionId, setSessionId] = useState(null);
    const [certificates, setCertificates] = useState([]);
    const [isKeystoreLoaded, setIsKeystoreLoaded] = useState(false); // <-- FIX: State to track if a keystore is active
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);

    useEffect(() => {
        // Generate a unique session ID on component mount
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
            setIsKeystoreLoaded(true); // <-- FIX: Set keystore as loaded on success
        } catch (err) {
            setError(err.message);
            setIsKeystoreLoaded(false); // <-- FIX: Ensure state is reset on error
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
        setIsKeystoreLoaded(false); // <-- FIX: Reset the keystore loaded state
        setError(null);
        // In a real app, you'd also invalidate the session on the backend
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
                        </div>
                    </div>
                )}

                {/* FIX: The main UI now depends on isKeystoreLoaded, not the number of certificates */}
                {isKeystoreLoaded ? (
                    <Dashboard
                        certificates={certificates}
                        sessionId={sessionId}
                        setCertificates={setCertificates}
                        setLoading={setLoading}
                        setError={setError}
                        endSession={endSession}
                    />
                ) : (
                    <WelcomeScreen
                        handleCreate={handleCreate}
                        handleUpload={handleUpload}
                        setLoading={setLoading}
                        setError={setError}
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
