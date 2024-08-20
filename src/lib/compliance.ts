import { Secp256k1, sha256 } from '@cosmjs/crypto';

// import { verifyADR36Amino } from '@keplr-wallet/cosmos';
import { Hdkey } from '@/constants/account';
import { BLOCKED_COUNTRIES, CountryCodes, OFAC_SANCTIONED_COUNTRIES } from '@/constants/geo';
import { LOCAL_STORAGE_VERSIONS, LocalStorageKey } from '@/constants/localStorage';
import { DydxAddress } from '@/constants/wallets';

import { getLocalStorage, setLocalStorage } from '@/lib/localStorage';

type KeplrComplianceStorage = {
  version?: string;
  [address: DydxAddress]: {
    pubKey?: string;
    signature?: DydxAddress;
  };
};

export const signComplianceSignature = async (
  message: string,
  action: string,
  status: string,
  hdkey: Hdkey
): Promise<{ signedMessage: string; timestamp: number }> => {
  if (!hdkey?.privateKey || !hdkey?.publicKey) {
    throw new Error('Missing hdkey');
  }

  const timestampInSeconds = Math.floor(Date.now() / 1000);
  const messageToSign: string = `${message}:${action}"${status || ''}:${timestampInSeconds}`;
  const messageHash = sha256(Buffer.from(messageToSign));

  const signed = await Secp256k1.createSignature(messageHash, hdkey.privateKey);
  const signedMessage = signed.toFixedLength();
  return {
    signedMessage: Buffer.from(signedMessage).toString('base64'),
    timestamp: timestampInSeconds,
  };
};

export const signComplianceSignatureKeplr = async (
  message: string,
  signer: DydxAddress,
  chainId: string
): Promise<{ signedMessage: string; pubKey: string }> => {
  if (!window.keplr) {
    throw new Error('Keplr not found');
  }

  const storedSignature = getLocalStorage<KeplrComplianceStorage>({
    key: LocalStorageKey.KeplrCompliance,
  });

  if (
    storedSignature &&
    storedSignature[signer] &&
    storedSignature[signer].pubKey &&
    storedSignature[signer].signature
  ) {
    return {
      signedMessage: storedSignature[signer].signature,
      pubKey: storedSignature[signer].pubKey,
    };
  }

  const { pub_key: pubKey, signature } = await window.keplr.signArbitrary(chainId, signer, message);

  setLocalStorage({
    key: LocalStorageKey.KeplrCompliance,
    value: {
      version: LOCAL_STORAGE_VERSIONS[LocalStorageKey.KeplrCompliance],
      [signer]: {
        pubKey: pubKey.value,
        signature,
      },
    },
  });

  // const pub = new Uint8Array(Buffer.from(pubKey.value, 'base64'));
  // const sig = new Uint8Array(Buffer.from(signature, 'base64'));

  // try {
  //   const isVerified = verifyADR36Amino(
  //     'dydx',
  //     'dydx1cew7z78590202eujzr799da2p2c5ssq7ahhxze',
  //     messageToSign,
  //     pub,
  //     sig,
  //     'secp256k1'
  //   );
  //   console.log('isVerified', isVerified);
  // } catch (e) {
  //   console.error('Error verifying signature', e);
  // }

  return {
    signedMessage: signature,
    pubKey: pubKey.value,
  };
};

export const isBlockedGeo = (geo: string): boolean => {
  return [...BLOCKED_COUNTRIES, ...OFAC_SANCTIONED_COUNTRIES].includes(geo as CountryCodes);
};
