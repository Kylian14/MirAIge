import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom'
import { AuthProvider, useAuth } from './auth'
import Login from './pages/Login'
import Layout from './components/Layout'
import Overview from './pages/Overview'
import Engagements from './pages/Engagements'
import Detection from './pages/Detection'
import Attacks from './pages/Attacks'
import Users from './pages/Users'

function Routed() {
  const { token } = useAuth()
  if (!token) return <Login />
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<Overview />} />
          <Route path="engagements" element={<Engagements />} />
          <Route path="detection" element={<Detection />} />
          <Route path="attacks" element={<Attacks />} />
          <Route path="users" element={<Users />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}

export default function App() {
  return (
    <AuthProvider>
      <Routed />
    </AuthProvider>
  )
}
