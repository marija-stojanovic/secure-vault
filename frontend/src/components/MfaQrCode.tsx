import { useEffect, useRef, useState } from 'react'
import QRCode from 'qrcode'

interface MfaQrCodeProps {
  provisioningUri: string
}

export function MfaQrCode({ provisioningUri }: MfaQrCodeProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const [error, setError] = useState('')

  useEffect(() => {
    if (!canvasRef.current || !provisioningUri) return

    QRCode.toCanvas(canvasRef.current, provisioningUri, {
      width: 220,
      margin: 2,
      errorCorrectionLevel: 'M',
      color: { dark: '#102a43', light: '#ffffff' },
    }).then(() => setError(''))
      .catch(() => setError('QR kod nije moguće prikazati. Upotrijebi ručni ključ.'))
  }, [provisioningUri])

  return (
    <div className="qr-panel">
      <span className="step-badge">1</span>
      <h3>Skeniraj QR kod</h3>
      <p>U Google ili Microsoft Authenticator aplikaciji izaberi dodavanje novog naloga i skeniraj kod.</p>
      <div className="qr-frame">
        <canvas ref={canvasRef} aria-label="QR kod za podešavanje MFA" />
      </div>
      {error && <p className="qr-error">{error}</p>}
    </div>
  )
}
