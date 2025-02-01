import React, { useState } from 'react';
const RegisterForm = () => {
  const [formData, setFormData] = useState({
    name: '',
    dob: '',
    gender: '',
    email: '',
    password: '',
    confirmPassword: '',
  });
  const [errors, setErrors] = useState({});
  const [message, setMessage] = useState('');

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const validateForm = () => {
    const newErrors = {};
    if (!formData.name) newErrors.name = "Name is required.";
    if (!formData.dob) newErrors.dob = "Date of birth is required.";
    if (!formData.gender) newErrors.gender = "Gender is required.";
    if (!formData.email) {
      newErrors.email = "Email is required.";
    } else {
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(formData.email)) newErrors.email = "Invalid email format.";
    }
    if (formData.password.length < 6) newErrors.password = "Password must be at least 6 characters.";
    if (formData.password !== formData.confirmPassword) {
      newErrors.confirmPassword = "Passwords do not match.";
    }
    return newErrors;
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    const newErrors = validateForm();
    if (Object.keys(newErrors).length > 0) {
      setErrors(newErrors);
      return;
    }

    try {
      const response = await fetch('http://localhost:5000/api/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData),
      });

      const data = await response.json();
      if (response.ok) {
        setMessage(data.message);
        setErrors({});
      } else {
        setMessage('');
        setErrors({ server: data.message });
      }
    } catch (error) {
      setErrors({ server: "An error occurred. Please try again later." });
    }
  };

  return (
    <div>
      <form onSubmit={handleSubmit}>
        <h1>REGISTRATION PAGE</h1>
        <label htmlFor="">Name</label>
        <input type="text" name="name" placeholder="Name" onChange={handleChange} />
        {errors.name && <p className="error">{errors.name}</p>}
        <label htmlFor="">Date Of Birth</label>
        <input type="date" name="dob" onChange={handleChange} />
        {errors.dob && <p className="error">{errors.dob}</p>}
<label htmlFor="">Gender</label>
        <select name="gender" onChange={handleChange}>
          <option value="">Select Gender</option>
          <option value="male">Male</option>
          <option value="female">Female</option>
          <option value="other">Other</option>
        </select>
        {errors.gender && <p className="error">{errors.gender}</p>}
         <label htmlFor="">Email</label>
        <input type="email" name="email" placeholder="Email" onChange={handleChange} />
        {errors.email && <p className="error">{errors.email}</p>}
        <label htmlFor="">Password</label>
        <input type="password" name="password" placeholder="Password" onChange={handleChange} />
        {errors.password && <p className="error">{errors.password}</p>}
        <label htmlFor="">Confirm Password</label>
        <input type="password" name="confirmPassword" placeholder="Confirm Password" onChange={handleChange} />
        {errors.confirmPassword && <p className="error">{errors.confirmPassword}</p>}

        <button type="submit">Register</button>
        {errors.server && <p className="error">{errors.server}</p>}
        {message && <p className="success">{message}</p>}
      </form>
    </div>
  );
};

export default RegisterForm;
