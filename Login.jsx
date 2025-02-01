import React, { useState } from 'react';
import { useForm } from 'react-hook-form';
import axios from 'axios';
import './login.css'
const LoginPage = () => {
  const { register, handleSubmit, formState: { errors } } = useForm();
  const [errorMessage, setErrorMessage] = useState('');

  const onSubmit = async (data) => {
    try {
      const response = await axios.post('http://localhost:5000/api/login', data);
      alert(response.data.message);
    } catch (error) {
      if (error.response) {
        setErrorMessage(error.response.data.message);
      } else {
        setErrorMessage('An unexpected error occurred.');
      }
    }
  };

  return (
    <div className="container mt-5">
      <h2>Login</h2>
      {errorMessage && <p className="text-danger">{errorMessage}</p>}
      <form onSubmit={handleSubmit(onSubmit)}>
        <div className="mb-3">
          <label>Email:</label>
          <input
            type="email"
            className="form-control"
            {...register('email', { required: 'Email is required' })}
          />
          {errors.email && <p className="text-danger">{errors.email.message}</p>}
        </div>
        <div className="mb-3">
          <label>Password:</label>
          <input
            type="password"
            className="form-control"
            {...register('password', { required: 'Password is required' })}
          />
          {errors.password && <p className="text-danger">{errors.password.message}</p>}
        </div>
        <button type="submit" className="btn btn-primary">Login</button>
      </form>
    </div>
  );
};

export default LoginPage;
