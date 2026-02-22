import React, { useState, useEffect } from "react";
import { useNavigate, useLocation } from "react-router-dom";
const Spinner = ({ path = "login" }) => {
  const [count, setCount] = useState(3);
  const navigate = useNavigate();
  const location = useLocation();

  useEffect(() => {
    const interval = setInterval(() => {
      setCount((prevValue) => --prevValue);
    }, 1000);
    
    if (count === 0) {
      // Validate the path
      if (!path || typeof path !== 'string' || path.trim() === '') {
        // Empty/blank path
        navigate('/login', { state: location.pathname });
      } 
      else if (path.startsWith('/') || path.endsWith('/')) {
        // Leading or trailing slash - NOT ALLOWED
        console.warn(`Path with leading/trailing slash "${path}" detected, redirecting to login`);
        navigate('/login', { state: location.pathname });
      }
      else if (path.includes('//') || path.includes('\\') || path.includes('..')) {
        // Path contains double slashes, backslashes, or traversal attempts
        console.warn(`Invalid path "${path}" detected, redirecting to login`);
        navigate('/login', { state: location.pathname });
      }
      else if (!/^[a-zA-Z0-9\-_/]+$/.test(path)) {
        // Path has invalid characters
        console.warn(`Invalid characters in path "${path}", redirecting to login`);
        navigate('/login', { state: location.pathname });
      }
      else {
        // Valid path
        navigate(`/${path}`, { state: location.pathname });
      }
    }
    
    return () => clearInterval(interval);
  }, [count, navigate, location, path]); // Added 'path' to dependencies

  return (
    <>
      <div
        className="d-flex flex-column justify-content-center align-items-center"
        style={{ height: "100vh" }}
      >
        <h1 className="Text-center">redirecting to you in {count} second </h1>
        <div className="spinner-border" role="status">
          <span className="visually-hidden">Loading...</span>
        </div>
      </div>
    </>
  );
};

export default Spinner;