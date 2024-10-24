import { useEffect, useState } from 'react';

import styled, { css } from 'styled-components';
import tw from 'twin.macro';

import { EvmDerivedAccountStatus, OnboardingSteps } from '@/constants/account';
import { AnalyticsEvents } from '@/constants/analytics';
import { DialogProps, OnboardingDialogProps } from '@/constants/dialogs';
import { STRING_KEYS } from '@/constants/localization';
import { isMainnet } from '@/constants/networks';
import { ConnectorType, WalletInfo, WalletType } from '@/constants/wallets';

import { useAccounts } from '@/hooks/useAccounts';
import { useBreakpoints } from '@/hooks/useBreakpoints';
import { useStringGetter } from '@/hooks/useStringGetter';

import breakpoints from '@/styles/breakpoints';

import { Dialog, DialogPlacement } from '@/components/Dialog';
import { GreenCheckCircle } from '@/components/GreenCheckCircle';
import { Ring } from '@/components/Ring';
import { WalletIcon } from '@/components/WalletIcon';
import { TestnetDepositForm } from '@/views/forms/AccountManagementForms/TestnetDepositForm';

import { calculateOnboardingStep } from '@/state/accountCalculators';
import { useAppSelector } from '@/state/appTypes';

import { track } from '@/lib/analytics/analytics';

import { DepositForm } from '../forms/AccountManagementForms/DepositForm';
import { ChooseWallet } from './OnboardingDialog/ChooseWallet';
import { GenerateKeys } from './OnboardingDialog/GenerateKeys';

export const OnboardingDialog = ({ setIsOpen }: DialogProps<OnboardingDialogProps>) => {
  const [derivationStatus, setDerivationStatus] = useState(EvmDerivedAccountStatus.NotDerived);

  const stringGetter = useStringGetter();
  const { isMobile } = useBreakpoints();

  const { selectWallet, sourceAccount } = useAccounts();

  const currentOnboardingStep = useAppSelector(calculateOnboardingStep);

  useEffect(() => {
    if (!currentOnboardingStep) setIsOpen(false);
  }, [currentOnboardingStep, setIsOpen]);

  const setIsOpenFromDialog = (open: boolean) => {
    setIsOpen(open);
  };

  const onChooseWallet = (wallet: WalletInfo) => {
    if (wallet.connectorType === ConnectorType.DownloadWallet) {
      window.open(wallet.downloadLink, '_blank');
      return;
    }
    if (wallet.name === WalletType.Privy || wallet.name === WalletType.Keplr) {
      setIsOpenFromDialog(false);
    }
    selectWallet(wallet);
  };

  return (
    <$Dialog
      isOpen={Boolean(currentOnboardingStep)}
      setIsOpen={setIsOpenFromDialog}
      {...(currentOnboardingStep &&
        {
          [OnboardingSteps.ChooseWallet]: {
            title: stringGetter({ key: STRING_KEYS.CONNECT_YOUR_WALLET }),
            description: stringGetter({ key: STRING_KEYS.CONNECT_YOUR_WALLET_SUBTITLE }),
            children: (
              <$Content>
                <ChooseWallet onChooseWallet={onChooseWallet} />
              </$Content>
            ),
          },
          [OnboardingSteps.KeyDerivation]: {
            slotIcon: {
              [EvmDerivedAccountStatus.NotDerived]: sourceAccount.walletInfo && (
                <WalletIcon wallet={sourceAccount.walletInfo} />
              ),
              [EvmDerivedAccountStatus.Deriving]: <$Ring withAnimation value={0.25} />,
              [EvmDerivedAccountStatus.EnsuringDeterminism]: <$Ring withAnimation value={0.25} />,
              [EvmDerivedAccountStatus.Derived]: <GreenCheckCircle />,
            }[derivationStatus],
            title: stringGetter({ key: STRING_KEYS.SIGN_MESSAGE }),
            description: stringGetter({ key: STRING_KEYS.SIGNATURE_CREATES_COSMOS_WALLET }),
            children: (
              <$Content>
                <GenerateKeys status={derivationStatus} setStatus={setDerivationStatus} />
              </$Content>
            ),
            width: '23rem',
          },
          [OnboardingSteps.DepositFunds]: {
            title: stringGetter({ key: STRING_KEYS.DEPOSIT }),
            description: !isMainnet && 'Test funds will be sent directly to your dYdX account.',
            children: (
              <$Content>
                {isMainnet ? (
                  <DepositForm
                    onDeposit={(event) => {
                      track(AnalyticsEvents.TransferDeposit(event ?? {}));
                    }}
                  />
                ) : (
                  <TestnetDepositForm
                    onDeposit={() => {
                      track(AnalyticsEvents.TransferFaucet());
                    }}
                  />
                )}
              </$Content>
            ),
          },
        }[currentOnboardingStep])}
      placement={isMobile ? DialogPlacement.FullScreen : DialogPlacement.Default}
    />
  );
};
const $Content = tw.div`flexColumn gap-1`;

const $Dialog = styled(Dialog)<{ width?: string }>`
  @media ${breakpoints.notMobile} {
    ${({ width }) =>
      width &&
      css`
        --dialog-width: ${width};
      `}
  }

  --dialog-icon-size: 1.25rem;
`;

const $Ring = tw(Ring)`w-1.25 h-1.25 [--ring-color:--color-accent]`;
