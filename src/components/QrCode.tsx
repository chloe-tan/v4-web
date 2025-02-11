import { memo, useEffect, useRef } from 'react';

import QRCodeStyling, { Options } from 'qr-code-styling';
import styled from 'styled-components';

import { useAppSelector } from '@/state/appTypes';
import { AppTheme } from '@/state/appUiConfigs';
import { getAppTheme } from '@/state/appUiConfigsSelectors';

type ElementProps = {
  value: string;
};

type StyleProps = {
  className?: string;
  hasLogo?: boolean;
  size?: number;
  options?: Partial<Options>;
};

const DARK_LOGO_MARK_URL = '/logos/logo-mark-dark.svg';
const LIGHT_LOGO_MARK_URL = '/logos/logo-mark-light.svg';

export const QrCode = memo(
  ({ className, value, hasLogo, size = 300, options }: ElementProps & StyleProps) => {
    const ref = useRef<HTMLDivElement>(null);
    const appTheme: AppTheme = useAppSelector(getAppTheme);

    const { current: qrCode } = useRef(
      new QRCodeStyling({
        type: 'svg',
        width: size,
        height: size,
        data: value,
        margin: 8,
        backgroundOptions: {
          color: 'var(--color-layer-4)',
        },
        imageOptions: {
          imageSize: 0.4,
          margin: 12,
        },
        dotsOptions: {
          type: 'dots',
          color: 'var(--color-text-2)',
        },
        cornersDotOptions: {
          type: 'square',
        },
        image: hasLogo
          ? appTheme === AppTheme.Light
            ? DARK_LOGO_MARK_URL
            : LIGHT_LOGO_MARK_URL
          : undefined,
        cornersSquareOptions: {
          type: 'extra-rounded',
          color: 'var(--color-text-2)',
        },
        qrOptions: {
          errorCorrectionLevel: 'M',
        },
        ...options,
      })
    );

    useEffect(() => {
      qrCode.append(ref.current ?? undefined);
    }, []);

    useEffect(() => {
      ref.current?.firstElementChild?.setAttribute('viewBox', `0 0 ${size} ${size}`);
    }, [ref.current]);

    useEffect(() => {
      if (hasLogo) {
        qrCode.update({
          image: appTheme === AppTheme.Light ? DARK_LOGO_MARK_URL : LIGHT_LOGO_MARK_URL,
        });
      }
    }, [appTheme, hasLogo]);

    return <$QrCode className={className} ref={ref} />;
  }
);
const $QrCode = styled.div`
  width: 100%;
  border-radius: 0.75em;

  svg {
    width: 100%;
    height: auto;
    border-radius: inherit;
    border: var(--border-width) solid var(--color-layer-6);
  }
`;
