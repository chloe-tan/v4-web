import { useRef, useState } from 'react';

import type { NumberFormatValues } from 'react-number-format';
import styled from 'styled-components';

import { ButtonShape, ButtonSize } from '@/constants/buttons';
import { STRING_KEYS } from '@/constants/localization';

import { useStringGetter } from '@/hooks/useStringGetter';

import { FormInput } from '@/components/FormInput';
import { Icon, IconName } from '@/components/Icon';
import { InputType } from '@/components/Input';
import { Output, OutputType } from '@/components/Output';
import { ToggleGroup } from '@/components/ToggleGroup';
import { WithConfirmationPopover } from '@/components/WithConfirmationPopover';

enum EditorState {
  Viewing = 'Viewing',
  Selecting = 'Selecting',
  Editing = 'Editing',
}

type ElementProps = {
  slippage: number;
  setSlippage: (slippage: number) => void;
  disabled?: boolean;
};

export type SlippageEditorProps = ElementProps;

export const SlippageEditor = ({ disabled, slippage, setSlippage }: SlippageEditorProps) => {
  const percentSlippage = slippage * 100;
  const [slippageInputValue, setSlippageInputValue] = useState(percentSlippage.toString());
  const [editorState, setEditorState] = useState(EditorState.Viewing);

  const stringGetter = useStringGetter();

  const slippageOptionItems = [
    { label: '0.1%', value: '0.001' },
    { label: '0.25%', value: '0.0025' },
    { label: stringGetter({ key: STRING_KEYS.CUSTOM }), value: 'custom' },
  ];
  const toggleGroupRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const onOpenChange = (isOpen: boolean) => {
    if (!isOpen) {
      setEditorState(EditorState.Viewing);
    }
  };

  const onCancel = () => {
    setEditorState(EditorState.Viewing);
    setSlippageInputValue(percentSlippage.toString());
  };

  const onChangeSlippage = ({ value }: NumberFormatValues) => {
    setSlippageInputValue(value);
  };

  const onConfirmSlippage = () => {
    setEditorState(EditorState.Viewing);
    setSlippage(Number(slippageInputValue) / 100);
  };

  const onSelectSlippage = (newSlippage: string) => {
    if (newSlippage === 'custom') {
      setEditorState(EditorState.Editing);
    } else {
      setSlippage(Number(newSlippage));

      setEditorState(EditorState.Viewing);
    }
  };

  if (disabled) {
    return <Output type={OutputType.Percent} value={slippage} />;
  }

  return (
    <WithConfirmationPopover
      open={editorState !== EditorState.Viewing}
      onOpenChange={onOpenChange}
      align="end"
      sideOffset={-22}
      asChild
      onCancel={onCancel}
      onConfirm={editorState === EditorState.Editing ? onConfirmSlippage : undefined}
      onClickTrigger={() => setEditorState(EditorState.Selecting)}
      slotTrigger={
        <div tw="row gap-[0.5ch] underline">
          <Output type={OutputType.Percent} value={slippage} />
          <Icon iconName={IconName.Pencil} />
        </div>
      }
      tw="w-10 text-[0.625rem]"
    >
      {
        {
          [EditorState.Viewing]: undefined,
          [EditorState.Selecting]: (
            <div tw="inlineRow justify-center rounded-[0.5em] bg-color-layer-2">
              <ToggleGroup
                ref={toggleGroupRef}
                items={slippageOptionItems}
                value={slippage.toString()}
                onValueChange={onSelectSlippage}
                shape={ButtonShape.Rectangle}
                size={ButtonSize.XSmall}
              />
            </div>
          ),
          [EditorState.Editing]: (
            <$FormInput
              type={InputType.Percent}
              value={slippageInputValue}
              ref={inputRef}
              onChange={onChangeSlippage}
              max={100}
            />
          ),
        }[editorState]
      }
    </WithConfirmationPopover>
  );
};
const $FormInput = styled(FormInput)`
  --form-input-height: 1.5rem;

  input {
    text-align: end;
  }
`;
