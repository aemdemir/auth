CREATE OR REPLACE FUNCTION update_updated_timestamp() RETURNS trigger AS $update_timestamp$
    BEGIN
        NEW.updated := NOW();
        RETURN NEW;
    END;
$update_timestamp$ LANGUAGE plpgsql;