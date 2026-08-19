import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Popup from './pages/Popup';
import AnalysisPage from './pages/AnalysisPage';
import Dashboard from './pages/Dashboard';

function App() {
  return (
    <Router>
      <Routes>
        <Route path="/" element={<Popup />} />
        <Route path="/analysis" element={<AnalysisPage />} />
        <Route path="/dashboard" element={<Dashboard />} />
      </Routes>
    </Router>
  );
}

export default App;
