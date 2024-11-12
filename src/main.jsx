import React from 'react'
import ReactDOM from 'react-dom/client'
import { createBrowserRouter, RouterProvider} from 'react-router-dom'
import App from './App.jsx'
import Chat from './chat.jsx'
import Register from './Register.jsx'
import './App.css'


const router = createBrowserRouter([
  {
    path: '/',
    element: <App/>,
    
    
  },
  {
    path: '/chat',
    element: <Chat/>
  },
  {
    path: '/register',
    element: <Register/>
  }
  ,
  
  
  

])
ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <RouterProvider router={router} />
  </React.StrictMode>,
)
