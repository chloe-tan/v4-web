import { isMainnet } from './networks';

export const OSMO_USDC_IBC_DENOM = isMainnet
  ? 'ibc/498A0751C798A0D9A389AA3691123DADA57DAA4FE165D5C75894505B876BA6E4'
  : 'ibc/DE6792CF9E521F6AD6E9A4BDF6225C9571A3B74ACC0A529F92BC5122A39D2E58';

export const NEUTRON_USDC_IBC_DENOM = isMainnet
  ? 'ibc/B559A80D62249C8AA07A380E2A2BEA6E5CA9A6F079C912C3A9E9B494105E4F81'
  : '';

export const SOLANA_USDC_DENOM = isMainnet ? 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v' : '';
