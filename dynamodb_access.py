import boto3

# EXAMPLE [[]]
# [list(("Firefox", "1.2.3", "UA_STR"))]

class DynamoDBAccess:
    def __init__(self, table_name, prim_key_name, region_name="us-east-1"):
        self.table_name = table_name
        self.prim_key_name = prim_key_name
        self.region_name = region_name
        dynamo_instance = boto3.resource("dynamodb", region_name=self.region_name)
        self.dynamo_table = dynamo_instance.Table(self.table_name)

    def add_to_table(self, prim_key, value_name, value_to_add):
        """Adds the value to the table if it does not already exist for the
        given key.
        
        Arguments:
            prim_key: primary key value for the table
            value_name: column name in the table
            value_to_add: 3 item list of ["Browser Name", "Browser Version",
                "UA String"]
        """
        
        item = self.get_value(prim_key)
        # the key exists, so we just need to update it
        if item is not None:
            # gets the correct column from the database for the given prim_key
            # should return back a list we can append to
            value = item[value_name]
            if value_to_add not in value:
                value.append(value_to_add)
                self.dynamo_table.update_item(
                        Key={
                            self.prim_key_name: prim_key
                            },
                        UpdateExpression="Set %s = :val1" % (value_name),
                        ExpressionAttributeValues={
                            ":val1": value
                            }
                        )

        # the key doesn't exist, so we have to create the initial input
        else:
            self.dynamo_table.put_item(
                    Item={
                        self.prim_key_name: prim_key,
                        # creates a list of lists of browsers
                        value_name: [value_to_add]
                        }
                    )


    def key_exists(self, prim_key):
        return self.get_value(prim_key) is not None

    def get_value(self, prim_key):
        response = self.dynamo_table.get_item(
                Key={
                    self.prim_key_name: prim_key
                    }
            )

        if response.get("Item", None) is not None:
            return response["Item"]

        return None

    def remove_key(self, prim_key):
        if self.key_exists(prim_key):
            ret = self.dynamo_table.delete_item(
                    Key={
                        self.prim_key_name: prim_key
                        }
                    )


# dynamodb = boto3.resource("dynamodb", region_name="us-east-1")
# table = dynamodb.Table("JA3Fingerprints")
# response = table.get_item(
#         Key={
#             "ja3": "testingkey"
#             }
#         )
# item = response["Item"]
# # print(response)
# all_browsers = item["browserinfo"]
# x = ["Firefox", "1.2.3", "UA_STR"]
# print(x in all_browsers)
# all_browsers.append(["Safari", "2.3.4", "SAFARI_UA_STR"])
# # print(item["browserinfo"])
# table.update_item(
#         Key={
#             "ja3": "testingkey"
#             },
#         UpdateExpression="SET browserinfo = :val1",
#         ExpressionAttributeValues={
#             ":val1": all_browsers
#             }
#         )

# # print(table.creation_date_time)

