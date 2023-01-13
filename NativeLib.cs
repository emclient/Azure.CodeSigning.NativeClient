using Azure.CodeSigning.Dlib.Core;
using Azure.CodeSigning.Dlib.Core.Models;
using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using Windows.Win32.Security.Cryptography;
using Windows.Win32.Foundation;
using static Windows.Win32.PInvoke;

namespace Azure.CodeSigning.NativeClient
{
    public class NativeLib
    {
        [UnmanagedCallersOnly(EntryPoint = "AuthenticodeDigestSignExWithFileHandle")]
        static unsafe int AuthenticodeDigestSignExWithFileHandle(
            CRYPT_INTEGER_BLOB* pMetadataBlob,
            uint digestAlgId,
            byte* pbToBeSignedDigest,
            uint cbToBeSignedDigest,
            IntPtr hFile,
            CRYPT_INTEGER_BLOB* pSignedDigest,
            CERT_CONTEXT** ppSignerCert,
            void* hCertChainStore)
        {
            try
            {
                //if (OperatingSystem.IsWindowsVersionAtLeast())

                byte[]? metadata = null;
                if (pMetadataBlob != null)
                {
                    metadata = new byte[pMetadataBlob->cbData];
                    fixed (byte *metadataPtr = metadata)
                    {
                        NativeMemory.Copy(pMetadataBlob->pbData, metadataPtr, pMetadataBlob->cbData);
                    }
                }

                byte[] digest = new byte[cbToBeSignedDigest];
                fixed (byte *digestPtr = digest)
                {
                    NativeMemory.Copy(pbToBeSignedDigest, digestPtr, cbToBeSignedDigest);
                }

                SafeFileHandle safeFileHandle = new SafeFileHandle(hFile, ownsHandle: false);

                AuthenticodeDigestSignResponse response = new DigestSigner(metadata).Sign(digestAlgId, digest, safeFileHandle);

                byte[] signature = response.Signature;
                pSignedDigest->cbData = (uint)signature.Length;
                pSignedDigest->pbData = (byte*)HeapAlloc(GetProcessHeap_SafeHandle(), 0, pSignedDigest->cbData);
                if (pSignedDigest->pbData == null)
                {
                    return HRESULT.E_OUTOFMEMORY;
                }

                fixed (byte *signaturePtr = signature)
                {
                    NativeMemory.Copy(signaturePtr, pSignedDigest->pbData, pSignedDigest->cbData);
                }

                if (response.SignerCert != null)
                {
                    CERT_CONTEXT *singerCertPtr = null;
                    try
                    {
                        singerCertPtr = CertDuplicateCertificateContext((CERT_CONTEXT*)response.SignerCert.Handle.ToPointer());
                        if (singerCertPtr == null)
                        {
                            return Marshal.GetHRForLastWin32Error();
                        }
                        if (CertAddCertificateContextToStore(new HCERTSTORE(hCertChainStore), singerCertPtr, 1, ppSignerCert) == false)
                        {
                            return Marshal.GetHRForLastWin32Error();
                        }
                    }
                    finally
                    {
                        if (singerCertPtr != null)
                        {
                            CertFreeCertificateContext(singerCertPtr);
                        }
                    }
                }

                if (response.IssuerCerts != null)
                {
                    foreach (var issuerCert in response.IssuerCerts)
                    {
                        CERT_CONTEXT *issuerCertPtr = null;
                        try
                        {
                            issuerCertPtr = CertDuplicateCertificateContext((CERT_CONTEXT*)issuerCert.Handle.ToPointer());
                            if (issuerCertPtr == null)
                            {
                                return Marshal.GetHRForLastWin32Error();
                            }
                            if (CertAddCertificateContextToStore(new HCERTSTORE(hCertChainStore), issuerCertPtr, 1, null) == false)
                            {
                                return Marshal.GetHRForLastWin32Error();
                            }
                        }
                        finally
                        {
                            if (issuerCertPtr != null)
                            {
                                CertFreeCertificateContext(issuerCertPtr);
                            }
                        }
                    }
                }

                return HRESULT.S_OK;
            }
            catch (Exception e)
            {
                Console.WriteLine("Unhandled exception:");
                Console.WriteLine(e);
                return HRESULT.E_FAIL;
            }
        }
    }
}
