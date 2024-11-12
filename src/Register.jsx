import React, { useState } from 'react';
import "./App.css";

const Register = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [message, setMessage] = useState('');
  const [color, setColor] = useState('black');

  const handleSubmit = async (e) => {
    e.preventDefault(); // Prevent the default form submission behavior

    const payload = { username, password };

    try {
      // Register user
      const response = await fetch('http://localhost:5000/register', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });

      const data = await response.json();

      if (response.ok) {
        setMessage(data.message);
        setColor('green'); // Successful registration message
        
        // Generate keys after registration
        await generateKeys(username); // Call to generate keys
      } else {
        setMessage(data.message);
        setColor('red'); // Error message
      }
    } catch (error) {
      console.error('Error during registration:', error);
      setMessage('An unexpected error occurred. Please try again.'); // Generic error message
    }
  };

  const generateKeys = async (username) => {
    const keyPair = await window.crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256"
      },
      true,
      ["encrypt", "decrypt"]
    );

    const publicKey = await window.crypto.subtle.exportKey("spki", keyPair.publicKey);
    
    // Send public key to the server
    await fetch('http://localhost:5000/api/storePublicKey', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        username,
        publicKey: btoa(String.fromCharCode(...new Uint8Array(publicKey))) // Base64 encode the public key
      })
    });

    // Store the private key securely (e.g., localStorage)
    const privateKey = await window.crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
    localStorage.setItem(`privateKey_${username}`, btoa(String.fromCharCode(...new Uint8Array(privateKey)))); // Store securely
  };

  return (
    <div className="login-container">
      <h2>Register</h2>
      <form onSubmit={handleSubmit}>
        <div className="input-group">
          <label htmlFor="username">Username</label>
          <input
            type="text"
            id="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder="Enter username"
            required
          />
        </div>

        <div className="input-group">
          <label htmlFor="password">Password</label>
          <input
            type="password"
            id="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder="Enter password"
            required
          />
        </div>

        <button type="submit">Register</button>
      </form>
      {message && <p className="message">{message}</p>} {/* Display message */}
      <div style={{ color: color }}>{message}</div>
    </div>
  );
};

export default Register;

