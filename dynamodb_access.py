"""DynamoDB AWS access module.

This module allows a user to access basic functions for the AWS DynamoDB
resource.

It wraps around boto3 functions for AWS.
"""

import boto3
from botocore.exceptions import ClientError

# EXAMPLE [[]]
# [list(("Firefox", "1.2.3", "UA_STR"))]

class DynamoDBAccess:
    """DynamoDBAccess is the class that wraps around current boto3 functions
    for the user to easily access DynamoDB instances."""

    def __init__(self, table_name, prim_key_name, region_name="us-east-1"):
        self.table_name = table_name
        self.prim_key_name = prim_key_name
        self.region_name = region_name

        dynamo_instance = boto3.resource("dynamodb", region_name=self.region_name)
        self.dynamo_table = dynamo_instance.Table(self.table_name)

        # checks the table exists
        self._check_table_exists()
        self._check_prim_key_exists()


    def _check_table_exists(self):
        """throws an exception if the table doesn't exist

        Returns:
            void
        """

        try:
            self.dynamo_table.table_status
        except ClientError as err:
            if err.response["Error"]["Code"] == "ResourceNotFoundException":
                raise TableDoesNotExistException("Table '%s' does not exist" % (self.table_name))

    def _check_prim_key_exists(self):
        """throws an exception if the table doesn't exist

        Returns:
            void
        """

        try:
            self.key_exists(self.prim_key_name)
        except ClientError as err:
            if err.response["Error"]["Code"] == "ValidationException":
                raise PrimKeyException("Primary Key '%s' not in '%s' Table" % \
                        (self.prim_key_name, self.table_name))


    def add_to_table(self, prim_key, value_name, value_to_add):
        """Adds the value to the table if it does not already exist for the
        given key.

        Args:
            prim_key: primary key value for the table
            value_name: column name in the table
            value_to_add: 3 item list of ["Browser Name", "Browser Version",
                "UA String"]

        Returns:
            void
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
        """Determines if the primary key exists in the table by attempting to
        get the value for the key.

        Args:
            prim_key (:obj: `str`) primary key name for the current DynamoDB Table

        Returns:
            bool if the key exists in the table
        """

        return self.get_value(prim_key) is not None

    def get_value(self, prim_key):
        """Gets the value of the primary key from the K-V pair in the Table

        Args:
            prim_key (:obj: `str`) name of the primary key to lookup in the Table

        Returns:
            Value associated with the primary key if it exists, None otherwise
        """

        response = self.dynamo_table.get_item(
            Key={
                self.prim_key_name: prim_key
            }
        )

        if response.get("Item", None) is not None:
            return response["Item"]

        return None


    def remove_key(self, prim_key):
        """Deletes the primary key and value from the table

        This first checks that the key exists in the table, then it attempts to
        delete it from the table.

        Args:
            prim_key (:obj: `str`) name of the primary key to delete from the Table

        Returns:
            void
        """

        if self.key_exists(prim_key):
            _ = self.dynamo_table.delete_item(
                Key={
                    self.prim_key_name: prim_key
                }
            )

class TableDoesNotExistException(Exception):
    """Inherits from Exception class and indicates that the Table specified in
    the DynamoDB instance does not exist"""


class PrimKeyException(Exception):
    """Inherits from Exception class and indicates that the Primary Key name
    specified in the DynamoDB instance does not exist"""
