﻿/*
* Copyright 2010-2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License").
* You may not use this file except in compliance with the License.
* A copy of the License is located at
*
*  http://aws.amazon.com/apache2.0
*
* or in the "license" file accompanying this file. This file is distributed
* on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
* express or implied. See the License for the specific language governing
* permissions and limitations under the License.
*/

#include <aws/dms/model/MessageFormatValue.h>
#include <aws/core/utils/HashingUtils.h>
#include <aws/core/Globals.h>
#include <aws/core/utils/EnumParseOverflowContainer.h>

using namespace Aws::Utils;


namespace Aws
{
  namespace DatabaseMigrationService
  {
    namespace Model
    {
      namespace MessageFormatValueMapper
      {

        static const int json_HASH = HashingUtils::HashString("json");
        static const int json_unformatted_HASH = HashingUtils::HashString("json-unformatted");


        MessageFormatValue GetMessageFormatValueForName(const Aws::String& name)
        {
          int hashCode = HashingUtils::HashString(name.c_str());
          if (hashCode == json_HASH)
          {
            return MessageFormatValue::json;
          }
          else if (hashCode == json_unformatted_HASH)
          {
            return MessageFormatValue::json_unformatted;
          }
          EnumParseOverflowContainer* overflowContainer = Aws::GetEnumOverflowContainer();
          if(overflowContainer)
          {
            overflowContainer->StoreOverflow(hashCode, name);
            return static_cast<MessageFormatValue>(hashCode);
          }

          return MessageFormatValue::NOT_SET;
        }

        Aws::String GetNameForMessageFormatValue(MessageFormatValue enumValue)
        {
          switch(enumValue)
          {
          case MessageFormatValue::json:
            return "json";
          case MessageFormatValue::json_unformatted:
            return "json-unformatted";
          default:
            EnumParseOverflowContainer* overflowContainer = Aws::GetEnumOverflowContainer();
            if(overflowContainer)
            {
              return overflowContainer->RetrieveOverflow(static_cast<int>(enumValue));
            }

            return {};
          }
        }

      } // namespace MessageFormatValueMapper
    } // namespace Model
  } // namespace DatabaseMigrationService
} // namespace Aws
